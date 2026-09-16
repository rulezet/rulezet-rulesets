import "pe"
rule _Trojan_Autorun_Gen_Trojan_Heur_D_cmIfbi3RsP_Trojan_Autorun_Gen__215 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP.vir, Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_1.vir, Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_10.vir, Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_2.vir, Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_3.vir, Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_4.vir, Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_5.vir, Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_6.vir, Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_7.vir, Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_8.vir, Trojan.Autorun_Gen.Trojan.Heur.D.cmIfbi3RsP_9.vir, Trojan.Danger_Trojan.GenericKD.72677122_210_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_211_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_212_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_213_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_214_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52c31c8366e8c8b72ca5fe1b249080ccd421a2a7d0f74f3f669cc54209cc85dc"
    hash2       = "bca9dabac131fbfad78bdce21c1d93857ae4ae4dcb229a4f74518ac3c87538c6"
    hash3       = "8352d55be073fdacd7ebe8394a536a600c77985e5255f81caddd5fc1a655e6f5"
    hash4       = "0d1b2c29b6876f07275d93de9b90f23c065050911ff56cb567b13e317174f918"
    hash5       = "b6e9ebfec10fd68bb1efc8cfef7fd6034c97a9e7fb18ac3de7dbb093212750b8"
    hash6       = "9497daede16e6ab182dc515f8f7665b86217f21147a0425d2054608b0036ac50"
    hash7       = "8feace36cec46aab756d2c33e423c9228132f00be2c31db58eea04d0f0dd968b"
    hash8       = "1f999beacd6a01b1cd7fac348f3d4c7ed03fffab4467a8119b2f2bf857a824b6"
    hash9       = "8c89f8b740dea148187e25796ac62d53edcb64f266926682d74f6e281322c12b"
    hash10      = "4483483409ae72c6d3ee5071c843e0b4921c134ec1461de681ba978e5abb2969"
    hash11      = "3a6194ee3f696ae3e2d4b12ac1ef2eaf7dc498b89882522aedcd32f3ad7afed7"
    hash12      = "21330120bc148d5673b6066519054750e66c7fa46512bd8800537a4c92ceec43"
    hash13      = "030898049eaa50ce7992482624814a2e0bf280e27d97bc124b1728b6df7a6efa"
    hash14      = "66e62dc1fd3c0f688f62115f4069b8cd68b2ded94dbe43b9542b74c9bc65ccc4"
    hash15      = "1342fb30e7a9905ebec2ad18251cd4b16dc17e2538e0eac58937accf52621717"
    hash16      = "4b31a1ccd6131c33b27c47661a382140289481f6be9bee812568e3527be1ea2d"
    hash17      = "005a1fa91b478ddeaf4ced94cb7dbd057412f8100a92bd58a0b76d71b3263d47"

  strings:
    $s1 = "Version&<" fullword ascii
    $s2 = "There was a general Excep" fullword ascii
    $s3 = "Close{@" fullword ascii
    $s4 = "$ program will no" fullword ascii
    $s5 = "Destroy(Re" fullword ascii
    $s6 = " Showy" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "1328d5238bea6d1bf49a45e35532b03e" and (all of them)
    ) or (all of them)
}