rule TTP_XOR_QUAD_CurrentVersionRun_667f {
  strings:
    $key_667f = { 35 10 [2] 11 1e [2] 3a 32 [2] 14 10 [2] 00 0b [2] 0f 11 [2] 11 0c [2] 13 0d [2] 08 0b [2] 14 0c [2] 08 23 }

  condition:
    any of them
}