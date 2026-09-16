rule TTP_XOR_QUAD_CurrentVersionRun_dea6 {
  strings:
    $key_dea6 = { 8d c9 [2] a9 c7 [2] 82 eb [2] ac c9 [2] b8 d2 [2] b7 c8 [2] a9 d5 [2] ab d4 [2] b0 d2 [2] ac d5 [2] b0 fa }

  condition:
    any of them
}