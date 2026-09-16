rule TTP_XOR_QUAD_CurrentVersionRun_6b6f {
  strings:
    $key_6b6f = { 38 00 [2] 1c 0e [2] 37 22 [2] 19 00 [2] 0d 1b [2] 02 01 [2] 1c 1c [2] 1e 1d [2] 05 1b [2] 19 1c [2] 05 33 }

  condition:
    any of them
}