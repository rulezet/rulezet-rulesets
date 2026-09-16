rule swscale_rgb2yuv_table__flt32___32_big_288_ {
  strings:
    $a0 = { 3f 37 17 59 3d 93 dd 98 3e 59 b3 d0 be c5 a1 cb 3f 00 00 00 bd eb 85 1f be e8 72 b0 bd 3c 6a 7f 3f 00 00 00 3f 37 17 59 3d 93 dd 98 3e 59 b3 d0 be c5 a1 cb 3f 00 00 00 bd eb 85 1f be e8 72 b0 bd 3c 6a 7f 3f 00 00 00 3f 16 45 a2 3d e9 78 d5 3e 99 16 87 be a9 78 d5 3f 00 00 00 be 2d 0e 56 be d6 87 2b bd a5 e3 54 3f 00 00 00 3f 16 45 a2 3d e9 78 d5 3e 99 16 87 be a9 78 d5 3f 00 00 00 be 2d 0e 56 be d6 87 2b bd a5 e3 54 3f 00 00 00 3f 17 0a 3d 3d e1 47 ae 3e 99 99 9a be a9 78 d5 3f 00 00 00 be 2d 0e 56 be d7 8d 50 bd a1 ca c1 3f 00 00 00 3f 16 45 a2 3d e9 78 d5 3e 99 16 87 be a9 78 d5 3f 00 00 00 be 2d 0e 56 be d6 87 2b bd a5 e3 54 3f 00 00 00 3f 16 45 a2 3d e9 78 d5 3e 99 16 87 be a9 78 d5 3f 00 00 00 be 2d 0e 56 be d6 87 2b bd a5 e3 54 3f 00 00 00 3f 33 74 bc 3d b2 2d 0e 3e 59 16 87 be c4 9b a6 3f 00 00 00 bd ed 91 68 be e3 d7 0a bd 61 47 ae 3f 00 00 00 }

  condition:
    $a0
}