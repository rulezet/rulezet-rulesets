import "elf"
rule mirai_sora_unpacked_arm {
  meta:
    description = "Mirai SORA unpacked (ARM)"
    author = "Andras Gemes"
    date = "2025-04-04"
    sha256 = "ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2"
    ref1 = "https://shadowshell.io/mirai-sora-botnet"
    ref2 = "https://bazaar.abuse.ch/sample/ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2"

  strings:
        $1 = "154.7.253.207"
        $2 = { af fb de de }
        $3 = { 07 1b 06 15 6e 74 35 24 24 38 31 20 74 3a 3b 20 74 32 3b 21 3a 30 54 00 }
        $4 = { 7b 36 3d 3a 7b 36 21 27 2d 36 3b 2c 74 07 1b 06 15 54 00 00 }
        $5 = { 17 3b 3a 3a 31 37 20 31 30 74 00 3b 74 17 1a 17 54 00 00 00 }
        $6 = { 7b 30 31 22 7b 23 35 20 37 3c 30 3b 33 54 00 }
        $7 = { 7b 30 31 22 7b 39 3d 27 37 7b 23 35 20 37 3c 30 3b 33 54 00 }
        $8 = { 51 74 00 00 }
        $9 = { 3b 33 3d 3a 54 00 }
        $10 = { 31 3a 20 31 26 54 00 }
        $11 = { 31 3a 35 36 38 31 54 00 }
        $12 = { 27 2d 27 20 31 39 54 00 }
        $13 = { 27 3c 54 00 }
        $14 = { 27 3c 31 38 38 54 00 }
        $15 = { 3a 37 3b 26 26 31 37 20 54 00 }
        $16 = { 7b 24 26 3b 37 7b 54 00 }
        $17 = { 7b 31 2c 31 54 00 }
        $18 = { 7a 35 3a 3d 39 31 54 00 }
        
    $19 = { 00 20 a0 e3 06 30 d2 e7 54 30 23 e2 06 30 c2 e7 01 20 82 e2 02 00 57 e1 ?? ?? ?? 1a }
        
    $20 = { 00 c0 a0 e3 00 20 9e e5 02 30 dc e7 03 30 20 e0 02 30 cc e7 00 10 9e e5 01 30 dc e7 03 30 26 e0 01 30 cc e7 00 20 9e e5 02 30 dc e7 03 30 25 e0 02 30 cc e7 00 10 9e e5 01 30 dc e7 03 30 24 e0 01 30 cc e7 04 20 de e5 01 30 d7 e5 01 c0 8c e2 03 24 82 e1 0c 00 52 e1 ?? ?? ?? ca }

  condition:
    defined(elf.type) and elf.machine == elf.EM_ARM and 13 of them
}