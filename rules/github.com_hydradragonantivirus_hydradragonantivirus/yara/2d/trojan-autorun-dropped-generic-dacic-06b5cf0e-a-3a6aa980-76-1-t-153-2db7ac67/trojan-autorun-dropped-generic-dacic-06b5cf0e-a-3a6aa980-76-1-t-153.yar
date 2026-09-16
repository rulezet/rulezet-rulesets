import "pe"
rule _Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_76_1_T_153 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_76_1.vir, Trojan.Homepage _Trojan.GenericKD.63563925.vir, Trojan.Homepage_Trojan.GenericKD.63563925.vir, Trojan.Homepage_Trojan.GenericKD.63563925_1.vir, Trojan.Homepage_Trojan.GenericKD.63563925_2.vir, Trojan.Homepage_Trojan.GenericKD.63563925_3.vir, Trojan.Homepage_Trojan.GenericKD.63563925_4.vir, Trojan.Homepage_Trojan.GenericKD.63563925_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.dyX@amUgp3c_8_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.dyX@amUgp3c_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.DyZ@a0Pysxf_5.vir, Virus.Infector_Trojan.GenericKD.63563925.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7afab3bcff29d766bee16cc525f4ce25459544885391d06aede2dff35c1e2ccf"
    hash2       = "8b4611cc77680eec12104fb7a4ada4c1de2f7526f09283f4c6fbf90959c4dadf"
    hash3       = "ca336d5847a044f476eedc996ba41528bf1fe00455761433fa81764978af5980"
    hash4       = "364f72635c94ee13e96d632e7ccc5ebce5d2735794c83895fb6d27d8184641b1"
    hash5       = "ffab8398b8b774a99ebf20a509788489e596e3c7aa035802552569b1fcebd7e3"
    hash6       = "6273ef7b5999c5972bffa211ce26dac76062aa05fbd4d1342bc5cb5cd9c8e490"
    hash7       = "7958890680798d12e73b6db667cbdf67e0bdb8b14d9c5207001a7c898296fa53"
    hash8       = "65c22a229a8224ae39a95c1f89cfbb993746949990fc7d4c6abbd5201f34fe83"
    hash9       = "a192133ff0d693d2ffa1af8687ebeb27dc225b8d506bf921c89fd7ce37f98093"
    hash10      = "f0d44cd4df4bcfa6a45d88206ebd96649a625cb44382eb3e3fcbba9948f6e8ef"
    hash11      = "98c73a9f16388398ddc6851cff8f8d73c8c61153d604ef9edfe4b8400d1e4d3e"
    hash12      = "229dc5eabfbe260eff230f71228a94707d292dccaa64922aa2fa79bc4ad4b31f"

  strings:
    $s1 = "lish XF" fullword ascii
    $s2 = "Adobe Photos" fullword ascii
    $s3 = "9 MoHa" fullword ascii
    $s4 = "Curr`r" fullword ascii
    $s5 = "*T$long" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "5f116d8e20f7d894b4b4ecbad1704009" and (all of them)
    ) or (all of them)
}