rule Virus_Hijack_Trojan_GenericKDZ_105924_218_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_218_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba2b0899331c1629d9fa089249ddbe9a85c402288993ee692e3c25080ba46bac"

  strings:
    $s1 = "<assemblyIdentity version=\"8.0.251.8\" processorArchitecture=\"X86\" name=\"Oracle Corporation, Java(tm) 2 Standard Edition\" t" ascii
    $s2 = "<assemblyIdentity version=\"8.0.251.8\" processorArchitecture=\"X86\" name=\"Oracle Corporation, Java(tm) 2 Standard Edition\" t" ascii
    $s3 = "PJava SE Runtime Environment 8 Update 25" fullword wide
    $s4 = "Could not open file '%Fs': %s" fullword ascii
    $s5 = "Ken Reneris. List Ver 1.0." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}