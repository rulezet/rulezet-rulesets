rule TTP_XOR_QUAD_CurrentVersionRun_6f2e {
  strings:
    $key_6f2e = { 3c 41 [2] 18 4f [2] 33 63 [2] 1d 41 [2] 09 5a [2] 06 40 [2] 18 5d [2] 1a 5c [2] 01 5a [2] 1d 5d [2] 01 72 }

  condition:
    any of them
}