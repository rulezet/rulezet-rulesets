rule _Virus_Autorun_Dropped_Win32_Worm_VB_NXJ_1_Virus_Danger_Win32_Wo_302 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Dropped.Win32.Worm.VB.NXJ_1.vir, Virus.Danger_Win32.Worm.VB.NZQ_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_10.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b5dc186b2c779853a25d3f0d3bc3470a319fb2d976594e000f7f06c23b18e03"
    hash2       = "86501b6f1f138531408efabe39c58b5c8e5f00c20916a0aa803ab7578d2d8c9d"
    hash3       = "e4ee7fbba33edc2cc6988fcacfd32e21fab0c423649695616f2433babc63ed2f"
    hash4       = "1335d89f83789bb79e7c84d5879b915ad18c39403427c0973f3ec9dd4e0cee1a"
    hash5       = "aea5d63d017533191174ccf1fefdc566525041ffcab87b390188dd572dc88e70"

  strings:
    $s1  = "EXECUTE ADD %s" fullword ascii
    $s2  = "EXECUTE PATCH %s" fullword ascii
    $s3  = "EXECUTE REMOVE %s" fullword ascii
    $s4  = "remove failed: %d,%d (%s)" fullword ascii
    $s5  = "copy_file: failed to open: %s,%d" fullword ascii
    $s6  = "copy_file: failed to open or stat: %d,%s,%d" fullword ascii
    $s7  = "copy_file: failed to read: %d" fullword ascii
    $s8  = "copy_file: failed to write: %d" fullword ascii
    $s9  = "PREPARE PATCH %s" fullword ascii
    $s10 = "PREPARE REMOVE %s" fullword ascii
    $s11 = "FINISH PATCH %s" fullword ascii
    $s12 = "FINISH REMOVE %s" fullword ascii
    $s13 = "PREPARE ADD %s" fullword ascii
    $s14 = "FINISH ADD %s" fullword ascii
    $s15 = "Usage: updater <dir-path> <parent-pid> [working-dir callback args...]" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}