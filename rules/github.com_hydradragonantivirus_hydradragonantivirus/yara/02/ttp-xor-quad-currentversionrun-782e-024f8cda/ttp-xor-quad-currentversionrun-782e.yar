rule TTP_XOR_QUAD_CurrentVersionRun_782e {
  strings:
    $key_782e = { 2b 41 [2] 0f 4f [2] 24 63 [2] 0a 41 [2] 1e 5a [2] 11 40 [2] 0f 5d [2] 0d 5c [2] 16 5a [2] 0a 5d [2] 16 72 }

  condition:
    any of them
}