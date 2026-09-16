rule TTP_XOR_QUAD_CurrentVersionRun_5d0e {
  strings:
    $key_5d0e = { 0e 61 [2] 2a 6f [2] 01 43 [2] 2f 61 [2] 3b 7a [2] 34 60 [2] 2a 7d [2] 28 7c [2] 33 7a [2] 2f 7d [2] 33 52 }

  condition:
    any of them
}