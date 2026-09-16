rule TTP_XOR_QUAD_CurrentVersionRun_7c7e {
  strings:
    $key_7c7e = { 2f 11 [2] 0b 1f [2] 20 33 [2] 0e 11 [2] 1a 0a [2] 15 10 [2] 0b 0d [2] 09 0c [2] 12 0a [2] 0e 0d [2] 12 22 }

  condition:
    any of them
}