rule TTP_XOR_QUAD_CurrentVersionRun_7a6f {
  strings:
    $key_7a6f = { 29 00 [2] 0d 0e [2] 26 22 [2] 08 00 [2] 1c 1b [2] 13 01 [2] 0d 1c [2] 0f 1d [2] 14 1b [2] 08 1c [2] 14 33 }

  condition:
    any of them
}