rule _Trojan_Autorun_Trojan_GenericKD_72869045_Virus_Hijack_Gen_Troja_350 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72869045.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4d08c1939546a758d6fe9b1b5284dc628aff3fef3cb798a4e535143a008a56"
    hash2       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash3       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash4       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"

  strings:
    $s1  = "[%s]GetOverlapped result failed %d " fullword wide
    $s2  = "CREATE TEMP TABLE sqlite_secondary(" fullword ascii
    $s3  = "[%s]Thread End" fullword wide
    $s4  = "[%s]NotifyAddrChange() failed with error %d" fullword wide
    $s5  = "[%s]WaitForSingleObject() failed with error %d" fullword wide
    $s6  = "[%s] already started" fullword wide
    $s7  = "[%s]Calling GetOverlappedResult() function" fullword wide
    $s8  = "[%s] Drop Failed... can not get the drop folder path." fullword wide
    $s9  = "   float g = y - 0.39173 * u - 0.81290 * v;" fullword ascii
    $s10 = "   float u = texture2D(s_texture_u, v_texcoord).r - 0.5;" fullword ascii
    $s11 = "   float v = texture2D(s_texture_v, v_texcoord).r - 0.5;" fullword ascii
    $s12 = "[%s]isStart TRUE" fullword wide
    $s13 = "[%s]isWatch FALSE" fullword wide
    $s14 = "Notifying address change" fullword wide
    $s15 = "[%s] > FileName is empty." fullword wide
    $s16 = "[%s] Try to check office program." fullword wide
    $s17 = "attribute vec4 position;" fullword ascii
    $s18 = "uniform sampler2D s_texture_v;" fullword ascii
    $s19 = "uniform sampler2D s_texture_y;" fullword ascii
    $s20 = "attribute vec2 texcoord;" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}