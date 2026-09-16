rule TTP_XOR_QUAD_CurrentVersionRun_312e {
  strings:
    $key_312e = { 62 41 [2] 46 4f [2] 6d 63 [2] 43 41 [2] 57 5a [2] 58 40 [2] 46 5d [2] 44 5c [2] 5f 5a [2] 43 5d [2] 5f 72 }

  condition:
    any of them
}