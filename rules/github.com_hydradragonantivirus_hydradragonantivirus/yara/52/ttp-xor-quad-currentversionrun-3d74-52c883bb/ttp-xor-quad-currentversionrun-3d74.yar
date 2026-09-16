rule TTP_XOR_QUAD_CurrentVersionRun_3d74 {
  strings:
    $key_3d74 = { 6e 1b [2] 4a 15 [2] 61 39 [2] 4f 1b [2] 5b 00 [2] 54 1a [2] 4a 07 [2] 48 06 [2] 53 00 [2] 4f 07 [2] 53 28 }

  condition:
    any of them
}