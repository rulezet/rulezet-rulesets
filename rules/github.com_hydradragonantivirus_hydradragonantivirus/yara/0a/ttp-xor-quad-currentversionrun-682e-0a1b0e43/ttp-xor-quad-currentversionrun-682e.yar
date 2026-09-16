rule TTP_XOR_QUAD_CurrentVersionRun_682e {
  strings:
    $key_682e = { 3b 41 [2] 1f 4f [2] 34 63 [2] 1a 41 [2] 0e 5a [2] 01 40 [2] 1f 5d [2] 1d 5c [2] 06 5a [2] 1a 5d [2] 06 72 }

  condition:
    any of them
}