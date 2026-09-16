rule TTP_XOR_QUAD_CurrentVersionRun_71ba {
  strings:
    $key_71ba = { 22 d5 [2] 06 db [2] 2d f7 [2] 03 d5 [2] 17 ce [2] 18 d4 [2] 06 c9 [2] 04 c8 [2] 1f ce [2] 03 c9 [2] 1f e6 }

  condition:
    any of them
}