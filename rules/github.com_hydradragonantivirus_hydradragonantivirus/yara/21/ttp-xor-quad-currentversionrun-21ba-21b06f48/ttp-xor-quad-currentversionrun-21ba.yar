rule TTP_XOR_QUAD_CurrentVersionRun_21ba {
  strings:
    $key_21ba = { 72 d5 [2] 56 db [2] 7d f7 [2] 53 d5 [2] 47 ce [2] 48 d4 [2] 56 c9 [2] 54 c8 [2] 4f ce [2] 53 c9 [2] 4f e6 }

  condition:
    any of them
}