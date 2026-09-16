rule TTP_XOR_QUAD_CurrentVersionRun_701f {
  strings:
    $key_701f = { 23 70 [2] 07 7e [2] 2c 52 [2] 02 70 [2] 16 6b [2] 19 71 [2] 07 6c [2] 05 6d [2] 1e 6b [2] 02 6c [2] 1e 43 }

  condition:
    any of them
}