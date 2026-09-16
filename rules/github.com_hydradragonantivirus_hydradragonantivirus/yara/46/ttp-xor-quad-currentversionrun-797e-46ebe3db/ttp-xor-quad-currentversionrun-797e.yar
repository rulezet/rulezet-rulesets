rule TTP_XOR_QUAD_CurrentVersionRun_797e {
  strings:
    $key_797e = { 2a 11 [2] 0e 1f [2] 25 33 [2] 0b 11 [2] 1f 0a [2] 10 10 [2] 0e 0d [2] 0c 0c [2] 17 0a [2] 0b 0d [2] 17 22 }

  condition:
    any of them
}