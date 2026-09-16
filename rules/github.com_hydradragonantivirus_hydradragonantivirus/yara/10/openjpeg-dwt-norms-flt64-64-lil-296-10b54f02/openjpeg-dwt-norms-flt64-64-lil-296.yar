rule OpenJPEG_dwt_norms__flt64___64_lil_296_ {
  strings:
    $a0 = { 00 00 00 00 00 00 f0 3f 00 00 00 00 00 00 f8 3f 00 00 00 00 00 00 06 40 00 00 00 00 00 80 15 40 5c 8f c2 f5 28 5c 25 40 d7 a3 70 3d 0a 57 35 40 f6 28 5c 8f c2 55 45 40 85 eb 51 b8 1e 55 55 40 66 66 66 66 66 56 65 40 cd cc cc cc cc 54 75 40 cf f7 53 e3 a5 9b f0 3f 46 b6 f3 fd d4 78 f9 3f 27 31 08 ac 1c 5a 07 40 1d 5a 64 3b df cf 16 40 29 5c 8f c2 f5 a8 26 40 a4 70 3d 0a d7 a3 36 40 00 00 00 00 00 a0 46 40 1f 85 eb 51 b8 9e 56 40 cd cc cc cc cc 9c 66 40 cf f7 53 e3 a5 9b f0 3f 46 b6 f3 fd d4 78 f9 3f 27 31 08 ac 1c 5a 07 40 1d 5a 64 3b df cf 16 40 29 5c 8f c2 f5 a8 26 40 a4 70 3d 0a d7 a3 36 40 00 00 00 00 00 a0 46 40 1f 85 eb 51 b8 9e 56 40 cd cc cc cc cc 9c 66 40 ad fa 5c 6d c5 fe e6 3f 56 7d ae b6 62 7f ed 3f c7 4b 37 89 41 60 f9 3f f2 d2 4d 62 10 58 08 40 fa 7e 6a bc 74 13 18 40 85 eb 51 b8 1e 05 28 40 00 00 00 00 00 00 38 40 5c 8f c2 f5 28 fc 47 40 ec 51 b8 1e 85 fb 57 40 }

  condition:
    $a0
}