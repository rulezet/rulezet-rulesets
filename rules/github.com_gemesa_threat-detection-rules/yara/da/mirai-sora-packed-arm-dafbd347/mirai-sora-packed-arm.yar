import "elf"
rule mirai_sora_packed_arm {
  meta:
    description = "Mirai SORA packed (ARM)"
    author = "Andras Gemes"
    date = "2025-04-04"
    sha256 = "ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2"
    ref1 = "https://shadowshell.io/mirai-sora-botnet"
    ref2 = "https://bazaar.abuse.ch/sample/ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2"

  strings:
    $1 = "UPX!"
    $2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    $3 = "$Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $"
    
    $4 = "y$Qdl%"
    $5 = "aym&,ZYeC"
    $6 = ":b[;tgo"
    $7 = "1`Rg{z"
    $8 = "R5&9Sc"
    $9 = "\\ME'Tj"
    $10 = "RSB$<|R"
    $11 = "a> ~!wqgUY"
    $12 = "fZ{Glb"
    $13 = "ld@j^]~"
    $14 = "902n	SP"
    $15 = "gP';H;"
    $16 = "~-%&xI"
    $17 = "0N?>BH"
    $18 = "8?oVM\\3"

  condition:
    defined(elf.type) and elf.machine == elf.EM_ARM and 13 of them
}