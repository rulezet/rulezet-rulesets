rule EPWIC_p_from_kurt_func__flt32___32_lil_164_ {
  strings:
    $a0 = { 51 2d ba 3e dc d9 e7 3e 28 10 0a 3f 87 c2 1f 3f 6b 28 35 3f 86 57 4a 3f 31 5e 5f 3f dd 45 74 3f 9c 8a 84 3f d1 e8 8e 3f 29 3f 99 3f f3 8e a3 3f 7f d9 ad 3f 75 1f b8 3f 7c 61 c2 3f 3c a0 cc 3f 5d dc d6 3f df 15 e1 3f 6a 4d eb 3f fd 82 f5 3f ed b6 ff 3f 9d f4 04 40 1b 0d 0a 40 1c 25 0f 40 75 3c 14 40 7a 53 19 40 d7 69 1e 40 e1 7f 23 40 96 95 28 40 f8 aa 2d 40 2f c0 32 40 e9 d4 37 40 79 e9 3c 40 b5 fd 41 40 c7 11 47 40 af 25 4c 40 6d 39 51 40 01 4d 56 40 42 60 5b 40 82 73 60 40 98 86 65 40 }

  condition:
    $a0
}