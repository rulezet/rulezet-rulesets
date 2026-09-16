rule _Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_7_2_Virus_Hijac_252 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.j8Z@a0q1@io_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.k4Z@aSzGK!f_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@a8oUJio_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.kAZ@aCEmdoo_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.l8Z@aKTibuk_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.LzZ@aWELKOd_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.muZ@aiy413e_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c19a4064f9ba6859fd14fb223c6a6d8c7b548352f33ae07be52e1d43be6fb004"
    hash2       = "0a342fecc5080aadf02bff772fa9d0f99058d7a668ff5b4a419e249a3dd1ef47"
    hash3       = "658599b056579d9aa4ac668be5740841f0dc91ac32df732d9021644b126ee909"
    hash4       = "fdc6e0242fdefc527344b693087d51360b11663e59f4f930436bd3809be7d553"
    hash5       = "975d93ca0607c3cf27dab47cdf5a4a9b9ab7b76694afdabb90acc9f7d45bdf35"
    hash6       = "6a2de974c19ec849189a89fbf09851b7ffd1ca00ec294cae7dc2c561dfcfb146"
    hash7       = "ae82b599c8f8af0c1e42d2f93d0b97a2066c55a05de68c41d70c171593d958bd"
    hash8       = "0d11528290f09e9bd8433c2cd8a7a5505736b7cc403c22c21ef75ad93bff8e7b"
    hash9       = "65311b62c205830c8267644b585fc20b45cbf550d2e72c0054e700e3585f3328"
    hash10      = "52e04767181f5e3fc800b23cbb50067ff234ffc60211c945b9854dede6acc614"
    hash11      = "e55ef04a8d60496e3b7c1952bffee49992145fa693507c523d67e9f49a11ebb3"
    hash12      = "08d10129a3e23aa52620c84f16f0d266e2c8e40d4d5f2680da91dd3a03f429d8"
    hash13      = "3a5b87aaf624bfa18224bbda4264f44234e35f728b592b208e3900225a546d18"
    hash14      = "1a277a5176b97114cb205028cb4aeebdada95fc80cb4e6fbaefcee193c4d0324"
    hash15      = "e49cc3940798fcedd43cc78e5fb016c5c4d13a14082e9dc15f416457268c6626"
    hash16      = "42dd93f893ab3883b1333d68ffe941bea87b0a21f858c7b1298590eaafabb740"
    hash17      = "af98772624b56471e6236d3a98f8fdaa9e2aac10244dd3acd396df8626e3edb7"

  strings:
    $s1  = "Sediment pack service is stopping - exiting shell iteration loop" fullword wide
    $s2  = "Failed to load DLL %s - HR = 0x%08x" fullword wide
    $s3  = "OS Version: %lu therefore the service will not run" fullword wide
    $s4  = "The sediment pack service failed to stop" fullword wide
    $s5  = "Remediates Windows Update Components" fullword wide
    $s6  = "Failed to delete iteration counts" fullword wide
    $s7  = "The sediment pack service stopped" fullword wide
    $s8  = "The sediment pack service was paused" fullword wide
    $s9  = "The sediment pack service continued" fullword wide
    $s10 = "The sediment pack service is shutting down" fullword wide
    $s11 = "Windows Remediation Service" fullword wide
    $s12 = "Current bytes %lli exceeds maximum" fullword wide
    $s13 = "pFound existing handle: %p" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}