rule TTP_XOR_QUAD_CurrentVersionRun_7c2e {
  strings:
    $key_7c2e = { 2f 41 [2] 0b 4f [2] 20 63 [2] 0e 41 [2] 1a 5a [2] 15 40 [2] 0b 5d [2] 09 5c [2] 12 5a [2] 0e 5d [2] 12 72 }

  condition:
    any of them
}