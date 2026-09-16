rule APT_acidbox_ssp_dll_module
{
    meta:
    
        description = "Rule to detect the SSP DLL component of AcidBox"
        author = "Marc Rivero | McAfee ATR Team"
        date = "2020-07-24"
        rule_version = "v1"
        malware_type = "backdoor"
        malware_family = "Backdoor:W32/Acidbox"
        actor_type = "APT"
        actor_group = "Turla"
        hash1 = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
    
    strings:

        $pattern_0 = { 49897ba0 8bc7 49894398 49897ba8 33c9 49894bb0 }
        $pattern_1 = { 8b8424a8000000 c1e818 88443108 66895c310a 498b0e }
        $pattern_2 = { 8b5f48 413bdd 410f47dd 85db 0f84f1000000 488b4720 4885c0 }
        $pattern_3 = { e8???????? 85c0 78c7 488d9424a0020000 488d8c24e0030000 ff15???????? 4c8bf8 }
        $pattern_4 = { ff15???????? 488bc8 4c8bc6 33d2 ff15???????? 8bfb 895c2420 }
        $pattern_5 = { 415f c3 4c8bdc 49895b10 }
        $pattern_6 = { 488d842488010000 4889442420 41bf???????? 458bcf 4c8bc7 418bd7 488d8c2490000000 }
        $pattern_7 = { c1e908 0fb6c9 3bce 77b6 8bd0 b9???????? c1ea10 }
        $pattern_8 = { 4c8bc3 ba???????? 488d4c2438 e8???????? 89442430 85c0 7508 }
        $pattern_9 = { bb02160480 8bc3 488b5c2440 488b742448 488b7c2450 4883c430 }
   
    condition:

        7 of them and 
        filesize < 199680
}