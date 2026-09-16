rule Borland_ebcdic_to_ascii__8_byt_256_ {
  strings:
    $a0 = { 00 01 02 03 5c 09 5c 7f 5c 5c 5c 0b 0c 0d 0e 0f 10 11 12 13 5c 5c 08 5c 18 19 5c 5c 1c 1d 1e 1f 5c 5c 5c 5c 5c 0a 17 1b 5c 5c 5c 5c 5c 05 06 07 5c 5c 16 5c 5c 5c 5c 04 5c 5c 5c 5c 14 15 5c 1a 20 5c 5c 5c 5c 5c 5c 5c 5c 5c 5b 2e 3c 28 2b 21 26 5c 5c 5c 5c 5c 5c 5c 5c 5c 5d 24 2a 29 3b 5e 2d 2f 5c 5c 5c 5c 5c 5c 5c 5c 7c 2c 25 5f 3e 3f 5c 5c 5c 5c 5c 5c 5c 5c 5c 60 3a 23 40 27 3d 22 5c 61 62 63 64 65 66 67 68 69 5c 5c 5c 5c 5c 5c 5c 6a 6b 6c 6d 6e 6f 70 71 72 5c 5c 5c 5c 5c 5c 5c 7e 73 74 75 76 77 78 79 7a 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 5c 7b 41 42 43 44 45 46 47 48 49 5c 5c 5c 5c 5c 5c 7d 4a 4b 4c 4d 4e 4f 50 51 52 5c 5c 5c 5c 5c 5c 5c 5c 53 54 55 56 57 58 59 5a 5c 5c 5c 5c 5c 5c 30 31 32 33 34 35 36 37 38 39 5c 5c 5c 5c 5c ff }

  condition:
    $a0
}