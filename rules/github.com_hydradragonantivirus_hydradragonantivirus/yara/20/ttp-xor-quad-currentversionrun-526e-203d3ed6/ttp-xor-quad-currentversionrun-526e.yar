rule TTP_XOR_QUAD_CurrentVersionRun_526e {
  strings:
    $key_526e = { 01 01 [2] 25 0f [2] 0e 23 [2] 20 01 [2] 34 1a [2] 3b 00 [2] 25 1d [2] 27 1c [2] 3c 1a [2] 20 1d [2] 3c 32 }

  condition:
    any of them
}