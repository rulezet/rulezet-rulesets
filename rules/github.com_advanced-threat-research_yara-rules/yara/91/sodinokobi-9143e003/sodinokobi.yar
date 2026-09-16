rule Sodinokobi
{
    meta:

        description = "This rule detect Sodinokobi Ransomware in memory in old samples and perhaps future."
        author      = "McAfee ATR team"
        rule_version = "v1"
        malware_type = "ransomware"
        malware_family = "Ransom:W32/Sodinokibi"
        actor_type = "Cybercrime"
        actor_group = "Unknown"
        version     = "1.0"
        
    strings:

        $a = { 40 0F B6 C8 89 4D FC 8A 94 0D FC FE FF FF 0F B6 C2 03 C6 0F B6 F0 8A 84 35 FC FE FF FF 88 84 0D FC FE FF FF 88 94 35 FC FE FF FF 0F B6 8C 0D FC FE FF FF }
        $b = { 0F B6 C2 03 C8 8B 45 14 0F B6 C9 8A 8C 0D FC FE FF FF 32 0C 07 88 08 40 89 45 14 8B 45 FC 83 EB 01 75 AA }

    condition:
    
        all of them
}