rule Windows_Trojan_Generic_4a773368 {
    meta:
        author = "Elastic Security"
        id = "4a773368-deaf-4248-b0ec-c4e924cc7428"
        fingerprint = "96329cbe576ba9772259c068916b928e7c33afcd18616ddd04d82227459d6a7f"
        creation_date = "2026-01-26"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "055bdcaa0b69a1e205c931547ef863531e9fdfdaac93aaea29fb701c7b468294"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $pdb = { 43 3A 5C 55 73 65 72 73 5C 41 64 6D 69 6E 69 73 74 72 61 74 6F 72 5C 44 65 73 6B 74 6F 70 5C E6 9B BF E6 8D A2 E9 85 8D E7 BD AE E6 96 87 E4 BB B6 5C 77 33 77 70 73 65 72 76 69 63 65 2D 73 76 63 68 6F 73 74 5C 78 36 34 5C 52 65 6C 65 61 73 65 5C 43 62 73 4D 73 67 41 70 69 2E 70 64 62 }
        $str1 = "AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD" wide fullword
        $str2 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" wide fullword
        $str3 = "ExcuteEnLargeDll failed with error code " fullword
        $str4 = "ChangeServiceConfig2 (SERVICE_CONFIG_DESCRIPTION) failed with error code" fullword
    condition:
        $pdb or 3 of ($str*)
}