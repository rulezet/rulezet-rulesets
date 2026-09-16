rule TTP_XOR_QUAD_CurrentVersionRun_f1ba {
  strings:
    $key_f1ba = { a2 d5 [2] 86 db [2] ad f7 [2] 83 d5 [2] 97 ce [2] 98 d4 [2] 86 c9 [2] 84 c8 [2] 9f ce [2] 83 c9 [2] 9f e6 }

  condition:
    any of them
}