rule OpenJPEG_dwt_norms__flt32___32_lil_148_ {
  strings:
    $a0 = { 00 00 80 3f 00 00 c0 3f 00 00 30 40 00 00 ac 40 48 e1 2a 41 52 b8 aa 41 14 ae 2a 42 f6 a8 aa 42 33 b3 2a 43 66 a6 aa 43 2f dd 84 3f a8 c6 cb 3f e5 d0 3a 40 fa 7e b6 40 ae 47 35 41 b8 1e b5 41 00 00 35 42 c3 f5 b4 42 66 e6 34 43 2f dd 84 3f a8 c6 cb 3f e5 d0 3a 40 fa 7e b6 40 ae 47 35 41 b8 1e b5 41 00 00 35 42 c3 f5 b4 42 66 e6 34 43 2b f6 37 3f 16 fb 6b 3f 0c 02 cb 3f 83 c0 42 40 a6 9b c0 40 f6 28 40 41 00 00 c0 41 48 e1 3f 42 29 dc bf 42 }

  condition:
    $a0
}