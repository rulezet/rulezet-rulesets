rule Whirlpool_rc__64_big_88_ {
  strings:
    $a0 = { 00 00 00 00 00 00 00 00 18 23 c6 e8 87 b8 01 4f 36 a6 d2 f5 79 6f 91 52 60 bc 9b 8e a3 0c 7b 35 1d e0 d7 c2 2e 4b fe 57 15 77 37 e5 9f f0 4a da 58 c9 29 0a b1 a0 6b 85 bd 5d 10 f4 cb 3e 05 67 e4 27 41 8b a7 7d 95 d8 fb ee 7c 66 dd 17 47 9e ca 2d bf 07 ad 5a 83 33 }

  condition:
    $a0
}