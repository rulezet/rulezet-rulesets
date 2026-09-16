rule Virus_Hijack_Gen_Trojan_ShellObject_luZ_amBwvTb_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.luZ@amBwvTb_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50990533da634d9d5f5f3ed6770357b286913e2926690300bf8dd7cd11d381a1"

  strings:
    $s1  = "sync USERID@gmail.com PASSWORD" fullword wide
    $s2  = " description" fullword wide
    $s3  = "corner test description " fullword wide
    $s4  = "GGItem.GetGGItemAt(): Index out of bound" fullword wide
    $s5  = "respond to blog" fullword wide
    $s6  = "Error: There is no list item of index -1" fullword wide
    $s7  = "GG is running. Press hotkey or click here to begin." fullword wide
    $s8  = "corner test description 0" fullword wide
    $s9  = "GGItem.Equals: Object passed in is not a GGItem object" fullword wide
    $s10 = "GGList.Equals: Object passed in is not a GGList object" fullword wide
    $s11 = "read book" fullword wide
    $s12 = "Please check Google Calendar: event0->description: 'local updated' appended" fullword wide
    $s13 = "DateParser.ConvertStringOutputIntoDateTime: Converted to " fullword wide
    $s14 = "No credentials received" fullword wide
    $s15 = "Invalid credentials received" fullword wide
    $s16 = "oct 13 things to do get my things done (((!##$#! 5pm" fullword wide
    $s17 = "add respond to blog #cs2101 24 nov" fullword wide
    $s18 = "Added respond to blog successfully" fullword wide
    $s19 = "Invoker: Invalid Input" fullword wide
    $s20 = "Invoker: " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}