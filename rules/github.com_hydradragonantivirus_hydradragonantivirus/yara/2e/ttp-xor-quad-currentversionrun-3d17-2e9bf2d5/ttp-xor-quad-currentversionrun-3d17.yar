rule TTP_XOR_QUAD_CurrentVersionRun_3d17 {
  strings:
    $key_3d17 = { 6e 78 [2] 4a 76 [2] 61 5a [2] 4f 78 [2] 5b 63 [2] 54 79 [2] 4a 64 [2] 48 65 [2] 53 63 [2] 4f 64 [2] 53 4b }

  condition:
    any of them
}