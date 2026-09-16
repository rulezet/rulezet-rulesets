rule TTP_XOR_QUAD_CurrentVersionRun_00ba {
  strings:
    $key_00ba = { 53 d5 [2] 77 db [2] 5c f7 [2] 72 d5 [2] 66 ce [2] 69 d4 [2] 77 c9 [2] 75 c8 [2] 6e ce [2] 72 c9 [2] 6e e6 }

  condition:
    any of them
}