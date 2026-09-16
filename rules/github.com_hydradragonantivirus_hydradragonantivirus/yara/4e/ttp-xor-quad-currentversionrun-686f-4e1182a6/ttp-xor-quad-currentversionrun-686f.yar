rule TTP_XOR_QUAD_CurrentVersionRun_686f {
  strings:
    $key_686f = { 3b 00 [2] 1f 0e [2] 34 22 [2] 1a 00 [2] 0e 1b [2] 01 01 [2] 1f 1c [2] 1d 1d [2] 06 1b [2] 1a 1c [2] 06 33 }

  condition:
    any of them
}