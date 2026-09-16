rule TTP_XOR_QUAD_CurrentVersionRun_5d7e {
  strings:
    $key_5d7e = { 0e 11 [2] 2a 1f [2] 01 33 [2] 2f 11 [2] 3b 0a [2] 34 10 [2] 2a 0d [2] 28 0c [2] 33 0a [2] 2f 0d [2] 33 22 }

  condition:
    any of them
}