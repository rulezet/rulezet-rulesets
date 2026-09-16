rule TTP_XOR_QUAD_CurrentVersionRun_3d57 {
  strings:
    $key_3d57 = { 6e 38 [2] 4a 36 [2] 61 1a [2] 4f 38 [2] 5b 23 [2] 54 39 [2] 4a 24 [2] 48 25 [2] 53 23 [2] 4f 24 [2] 53 0b }

  condition:
    any of them
}