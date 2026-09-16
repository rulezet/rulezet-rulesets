rule TTP_XOR_QUAD_CurrentVersionRun_e1ba {
  strings:
    $key_e1ba = { b2 d5 [2] 96 db [2] bd f7 [2] 93 d5 [2] 87 ce [2] 88 d4 [2] 96 c9 [2] 94 c8 [2] 8f ce [2] 93 c9 [2] 8f e6 }

  condition:
    any of them
}