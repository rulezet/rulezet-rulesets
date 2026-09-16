rule TTP_XOR_QUAD_CurrentVersionRun_666f {
  strings:
    $key_666f = { 35 00 [2] 11 0e [2] 3a 22 [2] 14 00 [2] 00 1b [2] 0f 01 [2] 11 1c [2] 13 1d [2] 08 1b [2] 14 1c [2] 08 33 }

  condition:
    any of them
}