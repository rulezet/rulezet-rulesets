rule TTP_XOR_QUAD_CurrentVersionRun_eea6 {
  strings:
    $key_eea6 = { bd c9 [2] 99 c7 [2] b2 eb [2] 9c c9 [2] 88 d2 [2] 87 c8 [2] 99 d5 [2] 9b d4 [2] 80 d2 [2] 9c d5 [2] 80 fa }

  condition:
    any of them
}