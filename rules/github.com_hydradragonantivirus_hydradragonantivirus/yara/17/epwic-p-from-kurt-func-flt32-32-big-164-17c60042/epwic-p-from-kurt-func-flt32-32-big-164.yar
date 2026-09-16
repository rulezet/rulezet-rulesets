rule EPWIC_p_from_kurt_func__flt32___32_big_164_ {
  strings:
    $a0 = { 3e ba 2d 51 3e e7 d9 dc 3f 0a 10 28 3f 1f c2 87 3f 35 28 6b 3f 4a 57 86 3f 5f 5e 31 3f 74 45 dd 3f 84 8a 9c 3f 8e e8 d1 3f 99 3f 29 3f a3 8e f3 3f ad d9 7f 3f b8 1f 75 3f c2 61 7c 3f cc a0 3c 3f d6 dc 5d 3f e1 15 df 3f eb 4d 6a 3f f5 82 fd 3f ff b6 ed 40 04 f4 9d 40 0a 0d 1b 40 0f 25 1c 40 14 3c 75 40 19 53 7a 40 1e 69 d7 40 23 7f e1 40 28 95 96 40 2d aa f8 40 32 c0 2f 40 37 d4 e9 40 3c e9 79 40 41 fd b5 40 47 11 c7 40 4c 25 af 40 51 39 6d 40 56 4d 01 40 5b 60 42 40 60 73 82 40 65 86 98 }

  condition:
    $a0
}