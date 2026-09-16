rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c846f6915cad2c8f0fd80391dbeaa94e04d9d9e6ddb4be3e808d5634aa6fe1d4"

  strings:
    $s1  = "usage: %s [-fvV?] [--force] [--verbose] [--version] [--help] [dirs]" fullword ascii
    $s2  = "\"%s\": error scanning" fullword ascii
    $s3  = "skipping, %d fonts, %d dirs" fullword ascii
    $s4  = "  -s, --system-only    scan system-wide directories only" fullword ascii
    $s5  = "%s: Can't init font config library" fullword ascii
    $s6  = "skipping, no write access" fullword ascii
    $s7  = "  -f, --force          scan directories with apparently valid caches" fullword ascii
    $s8  = "Can't create subdir list in \"%s\"" fullword ascii
    $s9  = "  -?, --help           display this help and exit" fullword ascii
    $s10 = "  -v, --verbose        display status information while busy" fullword ascii
    $s11 = "Can't save cache in \"%s\"" fullword ascii
    $s12 = "Can't create directory set" fullword ascii
    $s13 = "Can't create font set" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}