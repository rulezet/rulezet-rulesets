rule TTP_XOR_QUAD_CurrentVersionRun_766f {
  strings:
    $key_766f = { 25 00 [2] 01 0e [2] 2a 22 [2] 04 00 [2] 10 1b [2] 1f 01 [2] 01 1c [2] 03 1d [2] 18 1b [2] 04 1c [2] 18 33 }

  condition:
    any of them
}