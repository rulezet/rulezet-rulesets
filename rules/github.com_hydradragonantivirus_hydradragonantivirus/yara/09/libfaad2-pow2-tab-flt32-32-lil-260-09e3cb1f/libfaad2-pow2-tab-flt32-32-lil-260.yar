rule libfaad2_pow2_tab__flt32___32_lil_260_ {
  strings:
    $a0 = { 00 00 80 3f d2 64 81 3f 87 cd 82 3f 29 3a 84 3f c3 aa 85 3f 62 1f 87 3f 0f 98 88 3f d5 14 8a 3f c2 95 8b 3f df 1a 8d 3f 3a a4 8e 3f dc 31 90 3f d3 c3 91 3f 2b 5a 93 3f f0 f4 94 3f 2d 94 96 3f f0 37 98 3f 46 e0 99 3f 3a 8d 9b 3f da 3e 9d 3f 32 f5 9e 3f 51 b0 a0 3f 43 70 a2 3f 16 35 a4 3f d7 fe a5 3f 94 cd a7 3f 5b a1 a9 3f 3a 7a ab 3f 3f 58 ad 3f 79 3b af 3f f6 23 b1 3f c4 11 b3 3f f3 04 b5 3f 92 fd b6 3f af fb b8 3f 5b ff ba 3f a4 08 bd 3f 9a 17 bf 3f 4d 2c c1 3f cd 46 c3 3f 2a 67 c5 3f 75 8d c7 3f be b9 c9 3f 15 ec cb 3f 8c 24 ce 3f 34 63 d0 3f 1e a8 d2 3f 5b f3 d4 3f fd 44 d7 3f 16 9d d9 3f b8 fb db 3f f5 60 de 3f df cc e0 3f 89 3f e3 3f 07 b9 e5 3f 6a 39 e8 3f c7 c0 ea 3f 30 4f ed 3f ba e4 ef 3f 77 81 f2 3f 7d 25 f5 3f df d0 f7 3f b3 83 fa 3f 0c 3e fd 3f 00 00 00 40 }

  condition:
    $a0
}