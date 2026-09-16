rule TTP_XOR_QUAD_CurrentVersionRun_467e {
  strings:
    $key_467e = { 15 11 [2] 31 1f [2] 1a 33 [2] 34 11 [2] 20 0a [2] 2f 10 [2] 31 0d [2] 33 0c [2] 28 0a [2] 34 0d [2] 28 22 }

  condition:
    any of them
}