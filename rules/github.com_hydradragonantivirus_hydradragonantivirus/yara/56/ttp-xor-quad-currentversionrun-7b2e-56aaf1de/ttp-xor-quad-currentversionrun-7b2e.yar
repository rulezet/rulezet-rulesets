rule TTP_XOR_QUAD_CurrentVersionRun_7b2e {
  strings:
    $key_7b2e = { 28 41 [2] 0c 4f [2] 27 63 [2] 09 41 [2] 1d 5a [2] 12 40 [2] 0c 5d [2] 0e 5c [2] 15 5a [2] 09 5d [2] 15 72 }

  condition:
    any of them
}