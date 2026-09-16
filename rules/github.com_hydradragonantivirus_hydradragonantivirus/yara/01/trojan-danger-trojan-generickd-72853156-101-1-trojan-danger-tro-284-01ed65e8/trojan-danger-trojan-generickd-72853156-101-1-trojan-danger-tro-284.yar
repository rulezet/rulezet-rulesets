rule _Trojan_Danger_Trojan_GenericKD_72853156_101_1_Trojan_Danger_Tro_284 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_101_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_102_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_103_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_104_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_105_1.vir, Virus.Delself_Generic.Dacic.6D934B1C.A.2A40EF24.vir, Virus.Delself_Generic.Dacic.6D934B1C.A.2A40EF24_1.vir, Virus.Delself_Generic.Dacic.6D934B1C.A.470D9B3B.vir, Virus.Delself_Generic.Dacic.6D934B1C.A.8526A7CE.vir, Virus.Delself_Generic.Dacic.6D934B1C.A.A3F6C4BC.vir, Virus.Delself_Generic.Dacic.6D934B1C.A.D7790222.vir, Virus.Delself_Generic.Dacic.6D934B1C.A.FC5E33A2.vir, Virus.Delself_Generic.Dacic.6D934B1C.A.FC5E33A2_1.vir, Virus.Delself_Generic.Dacic.6D934B1C.A.FC5E33A2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_6_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_13.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_14.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81f5f30da52be1301366ec7349f536f3028145d13fc9c0a21ea9d5f7e090aa74"
    hash2       = "9b5bdcee5d5754ce4753af50720521ec3c418884f820e8712e9de5d7510b6da8"
    hash3       = "0414cb4b8251f82d8339696e61b156a6bb417e8178c5af96ba5ef06570e971a0"
    hash4       = "1cbc8b485e90dec26ca904b553beb88ed025fd2a2749692617a802099ceb4541"
    hash5       = "62dcb6224c2454581ad3e7454bb15c9496191bf7f1438a43a55e3dadf4fb39a9"
    hash6       = "a32d30f9396fc6114c8376809983b37d7343eb797f0157c826c272feb7639fbd"
    hash7       = "3c02f3bacf505cf3e3845a9c35ae85881f1441cd6c378a0ff534ff2b323c83b7"
    hash8       = "d8e29e7af6d8e203361c9bc720ce971bd88be6c3c7e1405d50a6b03ccf64922f"
    hash9       = "1552cd51b9c74992aef0ab6b5a87a3f9bcec4220872b19adf6cb102f11f902fc"
    hash10      = "e5b3e6f54e697967c56bddf6f0455d81efcc188f55d74ae43ffc5ca905f5b3b1"
    hash11      = "0b506bf0afe30ffc0cad3d2bf1f7320157fa6ee384ce5daa8b9581a3af654c1e"
    hash12      = "a34e498aa9592f2331da95561ebee253ed5616d79ecc40302a0ef4e1bda4ddcd"
    hash13      = "1942e43e79745a45954599d8429fae88c76b6c1314eab7f902fedb64c93d5db0"
    hash14      = "2600b605352a3bdafb62d825ef76d61bec37cb70ea05f6789075b6574cf8915d"
    hash15      = "a57b077abf8afc594d8b9ded28f2861ad2eb459be6e9b0835a2d88022618803e"
    hash16      = "64b112d5caa8661ad11d2e6782fb684cf181bfb265c92f6b31151ce05dd496c1"
    hash17      = "055cebf7b1a26aa7009eae824871941f9c691f46ee82f383ffd4216c9f21e024"
    hash18      = "95d29d1e3b0b672bd2b0d5e5f24e0fc808d8f23f0b05a9856672757cc56f5975"
    hash19      = "66b212fc6fa61082f7afd0b07f54ec411e5729cb124e4617330ed4fd1f0d17a0"
    hash20      = "a8757330e6c07b35a51e05e1f61d5f0400bd642b41f80132a851dcf98d3828e8"
    hash21      = "7ffbf664b74c8063b33bff8d07e3347f32fe83a84587c8badbe94a8ac6a565ca"
    hash22      = "8ede0f4de71832d8d907693134677538325f572e0f1fbe5ff06c34444bffab49"
    hash23      = "a5fc3a89690088f42331bf273baf111cc4843b0968bee6e5bc04e657bae56d85"
    hash24      = "d482f97583c2f40c05b3a3c48cbb6006ea81c19f8d8ce4ce6b8ece0d6a08cc1a"

  strings:
    $s1  = "Local APIC present (multiprocessor operation support)" fullword ascii
    $s2  = "CPUID: execution level not supported" fullword ascii
    $s3  = "Compare Exchange Eight Byte instruction available" fullword ascii
    $s4  = "Machine Check Exception supported" fullword ascii
    $s5  = "Page Size Extensions (4 MB pages supported)" fullword ascii
    $s6  = "ACPI support" fullword ascii
    $s7  = "self snoop" fullword ascii
    $s8  = "Time Stamp Counter and RDTSC instruction are available" fullword ascii
    $s9  = "Conditional MOVe instructions" fullword ascii
    $s10 = "Debug Trace Store" fullword ascii
    $s11 = "V86 Mode Extensions" fullword ascii
    $s12 = "ebout:blank" fullword ascii
    $s13 = "36 bit Page Size Extensions" fullword ascii
    $s14 = "Automatic clock control" fullword ascii
    $s15 = "3DNow! instructions available" fullword ascii
    $s16 = "Fast system calls (AMD only)" fullword ascii
    $s17 = "Fast system calls" fullword ascii
    $s18 = "Cannot acquire CPU information (CPUID not supported)" fullword ascii
    $s19 = "Physical Address Extensions (36-bit address, 2MB pages)" fullword ascii
    $s20 = "!'%s' is not a valid integer value '%d.%d' is not a valid timestampInvalid argument to time encode" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}