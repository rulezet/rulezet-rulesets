import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_94847_14_1_Trojan_Autorun_Troj_513 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.94847_14_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_210_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_229_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_261_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_32_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_335_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_360_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_462_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_51_1.vir, Virus.Danger_Gen.Trojan.ShellObject.i4Z@a0fL!hf.vir, Virus.Danger_Gen.Trojan.ShellObject.m4Z@a0fL!hf.vir, Virus.Hijack_Gen.Trojan.ShellObject.i4Z@a0fL!hf.vir, Virus.Hijack_Gen.Trojan.ShellObject.m4Z@a0fL!hf.vir, Virus.Hijack_Gen.Trojan.ShellObject.m4Z@a0fL!hf_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.m4Z@a0fL!hf_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m4Z@a0fL!hf_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.m4Z@a0fL!hf_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.v4Z@a0fL!hf.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cba309452b0fe1baba8b9bc7ea7833ae23e1aa4e543fa46102bb981741beef2e"
    hash2       = "f6ec42205132fb7d92b37283a15e1d85deb07f8366a6e21950fe9148b7521b64"
    hash3       = "64494670621c51764671081a61108348457b386b22de3e073b09efd0dd7ae439"
    hash4       = "d40cf8f96c552b5fd985c0d8af59d258dc09b81e6f02720755d0f742801caca2"
    hash5       = "57c6f74ba7c1852ef8c0b1236d2dd3a3447f5934d08d75c1be57ba1b8597d032"
    hash6       = "e4754a850e88395056493d13b8af02a47b8998abfe1aa1b1fb46cc6cea85ccea"
    hash7       = "247ad52a61d09323422af415253857c252b130cd5a35729f8030a33c51a08254"
    hash8       = "4669913f2309a05d9e57273a8688fb085802737fa3bb4c5045d917b3fd29bde2"
    hash9       = "ae8df917edc1d484a71f9f706144e5e18bde518ab2879d2cb6be222b2448581a"
    hash10      = "c771f465c82b2b36a350f1e231c90b640245d55ff8f2d0fcde49e9e697d816c2"
    hash11      = "08686d05baf0a3d2654a23f656b3231094801d8304bddbb2e323de79a1ae1252"
    hash12      = "3bd3eca41a72dcdbf6e1848c960ba6bc6a5bb3d0741e6ce65688ed09c8d6ea1f"
    hash13      = "c6d677c6ca91fc7b44dd873d2fa4a4782399bd9a0c3fd4eec9357b9bf096d447"
    hash14      = "ba2bc6d7fe5c823cd65cf5ea85244316e56d7040218ea2612c6e6807424d7b56"
    hash15      = "85c3e1e99594c3759cba67046240606ab0ce4dba8af000be5fb5a0ec5488afad"
    hash16      = "f1a2b97d00d61e246ef01139f8362e5f16697183cc083b5066946fefaf3d2d0a"
    hash17      = "0344522dbe37a443243f4acfaea7010b82793f03b37d215dc6db193a4d680b2e"
    hash18      = "dd8932efcd374e546c1b214d16c58550b25c84de8086974abeae76b372309885"

  strings:
    $s1 = "programs. The term Compensated Individual incluas the licensing rules which are listed below." fullword ascii
    $s2 = "programs. The term Compensated Individual incluTHEN A NY IMPLIED WARRA NTIES, GUA RA NTEES, OR CONDITIONS LAST ONLY DURING THE" fullword ascii
    $s3 = "programs. The term Compensated Individual inclu" fullword ascii
    $s4 = "services ordered and Oracle may end this agreement. Provisions that survive termination or expiration include those relating tog" ascii
    $s5 = "Failure. During online activation, if the licensing or activation functions of the software are" fullword ascii
    $s6 = "services ordered and Oracle may end this agreement. Provisions that survive termination or expiration include those relating tog" ascii
    $s7 = "ng or activation functions of the software are" fullword ascii
    $s8 = "dispute under this agreement to which Section B applie" fullword ascii
    $s9 = "ivation, if the licensing or activation functions of the software are" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "5de807e4e804b14f8faf5760f1add8dc" and (all of them)
    ) or (all of them)
}