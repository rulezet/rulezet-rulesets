rule OpenJPEG_dwt_norms__flt32___32_big_148_ {
  strings:
    $a0 = { 3f 80 00 00 3f c0 00 00 40 30 00 00 40 ac 00 00 41 2a e1 48 41 aa b8 52 42 2a ae 14 42 aa a8 f6 43 2a b3 33 43 aa a6 66 3f 84 dd 2f 3f cb c6 a8 40 3a d0 e5 40 b6 7e fa 41 35 47 ae 41 b5 1e b8 42 35 00 00 42 b4 f5 c3 43 34 e6 66 3f 84 dd 2f 3f cb c6 a8 40 3a d0 e5 40 b6 7e fa 41 35 47 ae 41 b5 1e b8 42 35 00 00 42 b4 f5 c3 43 34 e6 66 3f 37 f6 2b 3f 6b fb 16 3f cb 02 0c 40 42 c0 83 40 c0 9b a6 41 40 28 f6 41 c0 00 00 42 3f e1 48 42 bf dc 29 }

  condition:
    $a0
}