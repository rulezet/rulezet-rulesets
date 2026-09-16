rule TTP_XOR_QUAD_CurrentVersionRun_3d4b {
  strings:
    $key_3d4b = { 6e 24 [2] 4a 2a [2] 61 06 [2] 4f 24 [2] 5b 3f [2] 54 25 [2] 4a 38 [2] 48 39 [2] 53 3f [2] 4f 38 [2] 53 17 }

  condition:
    any of them
}