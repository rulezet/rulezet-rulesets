rule TTP_XOR_QUAD_CurrentVersionRun_3d65 {
  strings:
    $key_3d65 = { 6e 0a [2] 4a 04 [2] 61 28 [2] 4f 0a [2] 5b 11 [2] 54 0b [2] 4a 16 [2] 48 17 [2] 53 11 [2] 4f 16 [2] 53 39 }

  condition:
    any of them
}