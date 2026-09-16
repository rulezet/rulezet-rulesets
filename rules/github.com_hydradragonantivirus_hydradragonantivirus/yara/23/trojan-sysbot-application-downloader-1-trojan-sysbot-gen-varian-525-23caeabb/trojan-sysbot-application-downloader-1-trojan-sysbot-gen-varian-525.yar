import "pe"
rule _Trojan_Sysbot_Application_Downloader_1_Trojan_Sysbot_Gen_Varian_525 {
  meta:
    description = "datamaliciousorder - from files Trojan.Sysbot_Application.Downloader_1.vir, Trojan.Sysbot_Gen.Variant.Ransom.VirLock.100_19_1.vir, Virus.Infector_Trojan.GenericKDZ.96072_10.vir, Virus.Infector_Trojan.GenericKDZ.96072_13.vir, Virus.Infector_Trojan.GenericKDZ.96072_18.vir, Virus.Infector_Trojan.GenericKDZ.96072_40.vir, Virus.Infector_Trojan.GenericKDZ.96072_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aab1798b5551125cab1635e001fd1b6a3866f6ca0eb7e55e7520eb13446a5d96"
    hash2       = "0997e66d1d973ed9c0c1a2a5367b46dcaf1d061c5dec73c3f575b01149e82b25"
    hash3       = "064946b29847ff8214aa6590208ca8264884328372fbdee6c078be9016111e06"
    hash4       = "e73f8525fdb3a22fb5abb628989b9b357248216db2e09267abfb7e573e54268d"
    hash5       = "0a8354f10dabd36911df72e80fb999c2e380001f04634f676ddc4800c3a0bd9e"
    hash6       = "36ef145c7935ba7116b0951a0e90f2cbbefe4d6a7207de748c57e1acca8a7197"
    hash7       = "9d76b8699694d76a82861bc9b72c6af5106748d80fc720e7b29ab1c9e127f50d"

  strings:
    $s1 = "device will be counted as a named user plus inthe forward link into your browser window. THE ADDITIONAL TERMS CONTA IN A BINDING" ascii
    $s2 = "Field Technician: is defined as an engineer, " fullword ascii
    $s3 = "ligated party; government restrictions" fullword ascii
    $s4 = "e servers, regardless of whether or not the individual is actively using the programs at any given time." fullword ascii
    $s5 = "lion U.S. dollars (Seven hundred and seventy-two thousand four" fullword ascii
    $s6 = "ransaction Volume: is defined as one million U.S. dollars (Seven hundred and seventy-two thousand four" fullword ascii
    $s7 = " Transaction Volume: is defined as one million U.S. dollars (Seven hundred and seventy-two thousand four" fullword ascii
    $s8 = "Field Technician: is defined as an engineer, God; electrical, internet, or telecommunication outage that is not caused by the ob" ascii
    $s9 = "Field Technician: is defined as an engineer, God; electrical, internet, or telecommunication outage that is not caused by the ob" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "5d69545471a880b28d8e430c48545ebe" and (all of them)
    ) or (all of them)
}