rule TTP_XOR_QUAD_CurrentVersionRun_384b {
  strings:
    $key_384b = { 6b 24 [2] 4f 2a [2] 64 06 [2] 4a 24 [2] 5e 3f [2] 51 25 [2] 4f 38 [2] 4d 39 [2] 56 3f [2] 4a 38 [2] 56 17 }

  condition:
    any of them
}