import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_238_2_Vir_103 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_238_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_24_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_2_1.vir, Virus.Sysbot_Trojan.GenericKD.61340032_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5737e7951ee35d1c250124a7e9a39ecdb2af67999fad09b91cfb17e0e744bbd"
    hash2       = "a9993c32ba563caa1d5189a138ebd607fa15cfbbf9dd6124f11215f9803cc036"
    hash3       = "aa619da09e3fec8627d139e888381ef1dfd8bc79a67b8f473be0ae2e40619c35"
    hash4       = "fe68fa8aa8522badacc0c97554cd4a1b8d466dd16dc61b86542e799db0d1f7ae"

  strings:
    $s1  = "Email: contact@njtsoftware.com" fullword wide
    $s2  = "El territorio debe contener 1 sector como m" fullword wide
    $s3  = "Se ha encontrado un error en el archivo." fullword wide
    $s4  = "Error al asociar la extensi" fullword wide
    $s5  = "Error al desasociar la extensi" fullword wide
    $s6  = "adir un sector" fullword wide
    $s7  = "mero de territorio" fullword wide
    $s8  = "KVLC media player, VideoLAN and x264 are registered trademarks from VideoLAN" fullword ascii
    $s9  = "Todos los sectores deben tener nombre." fullword wide
    $s10 = " un sector entero. Aunque lo haya vuelto a a" fullword wide
    $s11 = "Mover el sector abajo" fullword wide
    $s12 = "Mover el sector arriba" fullword wide
    $s13 = "Eliminar el sector" fullword wide
    $s14 = "Nuevo sector" fullword wide
    $s15 = " seguro que desea eliminar este sector?" fullword wide
    $s16 = "Cuenta total de puertas" fullword wide
    $s17 = "Mover la puerta arriba" fullword wide
    $s18 = "Mover la puerta abajo" fullword wide
    $s19 = "Sector seleccionado" fullword wide
    $s20 = "Territory Manager File|*.terr" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (8 of them)
    ) or (all of them)
}