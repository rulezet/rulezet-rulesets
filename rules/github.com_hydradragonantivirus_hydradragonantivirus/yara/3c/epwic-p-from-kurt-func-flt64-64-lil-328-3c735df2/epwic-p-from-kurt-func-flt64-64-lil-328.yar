rule EPWIC_p_from_kurt_func__flt64___64_lil_328_ {
  strings:
    $a0 = { 6d 53 3c 2e aa 45 d7 3f 4d 14 21 75 3b fb dc 3f e6 07 ae f2 04 42 e1 3f ad a4 15 df 50 f8 e3 3f ca 8d 22 6b 0d a5 e6 3f a3 5c 1a bf f0 4a e9 3f ac e0 b7 21 c6 eb eb 3f b2 66 64 90 bb 88 ee 3f e1 97 fa 79 53 91 f0 3f 93 35 ea 21 1a dd f1 3f 9d 68 57 21 e5 27 f3 3f c4 42 ad 69 de 71 f4 3f d0 d5 56 ec 2f bb f5 3f a4 aa 09 a2 ee 03 f7 3f 23 4a 7b 83 2f 4c f8 3f 32 3d 61 89 07 94 f9 3f b3 0c 71 ac 8b db fa 3f a6 b8 aa ec bb 22 fc 3f ef c9 c3 42 ad 69 fd 3f 8e 40 bc ae 5f b0 fe 3f f4 e0 ee ac dd f6 ff 3f 91 d5 ad 9e 93 9e 00 40 c4 b1 2e 6e a3 41 01 40 4d 67 27 83 a3 e4 01 40 f3 93 6a 9f 8e 87 02 40 26 fc 52 3f 6f 2a 03 40 77 db 85 e6 3a cd 03 40 55 f6 5d 11 fc 6f 04 40 c2 4c db bf b2 12 05 40 be de fd f1 5e b5 05 40 80 0e f3 e5 05 58 06 40 98 17 60 1f 9d fa 06 40 77 be 9f 1a 2f 9d 07 40 e4 a0 84 99 b6 3f 08 40 18 21 3c da 38 e2 08 40 14 3f c6 dc b5 84 09 40 d7 fa 22 a1 2d 27 0a 40 61 54 52 27 a0 c9 0a 40 79 e9 26 31 08 6c 0b 40 91 7e fb 3a 70 0e 0c 40 70 b1 a2 06 d3 b0 0c 40 }

  condition:
    $a0
}