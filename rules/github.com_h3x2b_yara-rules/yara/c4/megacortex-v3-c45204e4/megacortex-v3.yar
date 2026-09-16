rule megacortex_v3 : malware ransomware
{
    meta:
        description = "Megacortex ransomware v3 - M3GA-W8="
        author = "tracker [_at] h3x.eu"
        
    strings:
        $megacortex_1 = "M3GA-W8="
        $megacortex_2 = "Your companies network has been breached and infected with MegaCortex Malware."

    condition:
                 uint16be(0) == 0x4d5a and
        any of ( $megacortex_* )
}