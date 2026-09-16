rule TTP_XOR_QUAD_CurrentVersionRun_3d25 {
  strings:
    $key_3d25 = { 6e 4a [2] 4a 44 [2] 61 68 [2] 4f 4a [2] 5b 51 [2] 54 4b [2] 4a 56 [2] 48 57 [2] 53 51 [2] 4f 56 [2] 53 79 }

  condition:
    any of them
}