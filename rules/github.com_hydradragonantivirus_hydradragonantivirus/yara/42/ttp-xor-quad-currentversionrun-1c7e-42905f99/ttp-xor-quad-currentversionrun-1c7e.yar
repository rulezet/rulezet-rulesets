rule TTP_XOR_QUAD_CurrentVersionRun_1c7e {
  strings:
    $key_1c7e = { 4f 11 [2] 6b 1f [2] 40 33 [2] 6e 11 [2] 7a 0a [2] 75 10 [2] 6b 0d [2] 69 0c [2] 72 0a [2] 6e 0d [2] 72 22 }

  condition:
    any of them
}