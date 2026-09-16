rule APT_EQGRP_SUCTIONCHAR_BVP47_1 {
  meta:
    author      = "@qutluch@infosec.exchange"
    description = "Code overlap between EQGRP SUCTIONCHAR and BVP47."
    reference   = "https://github.com/x0rz/EQGRP"
    reference   = "https://www.virustotal.com/gui/collection/43334ea6fbd9e71384d7c3c299f6a7472b35d6930b95caedd25764f09513ca60"
    reference   = "https://www.virustotal.com/gui/collection/alienvault_62165a9098875d0f12e0d0a8"
    DaysofYARA  = "23/100"
    license     = "BSD-2-Clause"
    date        = "2024-01-31"
    version     = "1.0"
    hash        = "7989032a5a2baece889100c4cfeca81f1da1241ab47365dad89107e417ce7bac"
    hash        = "81479e151a090288793a4c449f70a94a7a285dfd86178f2d407d1915536c0105"
    hash        = "df79815b6fa50dfdd626be2d20a9e5d0741e4ceed4fd49da9f62ef4ecbc127a7"

  strings:
    $ = { 3C 24 89 D1 BA A1 2F B8 44 C1 E9 06 69 C1 E8 03 00 00 03 4D E0 29 C3 69 DB 40 42 0F 00 69 45 E4 E8 03 00 00 01 C3 89 D8 F7 EA 89 D8 C1 F8 1F C1 FA 1C 29 C2 8D 0C 0A 69 D2 00 CA 9A 3B 8D 45 D0 89 4D }

  condition:
    uint32(0) == 0x464c457f
    and all of them
}