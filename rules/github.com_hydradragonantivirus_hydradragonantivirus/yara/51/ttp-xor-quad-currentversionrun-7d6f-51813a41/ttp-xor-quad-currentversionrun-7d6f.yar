rule TTP_XOR_QUAD_CurrentVersionRun_7d6f {
  strings:
    $key_7d6f = { 2e 00 [2] 0a 0e [2] 21 22 [2] 0f 00 [2] 1b 1b [2] 14 01 [2] 0a 1c [2] 08 1d [2] 13 1b [2] 0f 1c [2] 13 33 }

  condition:
    any of them
}