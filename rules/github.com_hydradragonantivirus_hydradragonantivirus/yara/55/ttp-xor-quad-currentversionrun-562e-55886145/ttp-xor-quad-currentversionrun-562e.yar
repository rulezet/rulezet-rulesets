rule TTP_XOR_QUAD_CurrentVersionRun_562e {
  strings:
    $key_562e = { 05 41 [2] 21 4f [2] 0a 63 [2] 24 41 [2] 30 5a [2] 3f 40 [2] 21 5d [2] 23 5c [2] 38 5a [2] 24 5d [2] 38 72 }

  condition:
    any of them
}