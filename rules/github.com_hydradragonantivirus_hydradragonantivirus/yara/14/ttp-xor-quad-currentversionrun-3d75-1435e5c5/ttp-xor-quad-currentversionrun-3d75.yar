rule TTP_XOR_QUAD_CurrentVersionRun_3d75 {
  strings:
    $key_3d75 = { 6e 1a [2] 4a 14 [2] 61 38 [2] 4f 1a [2] 5b 01 [2] 54 1b [2] 4a 06 [2] 48 07 [2] 53 01 [2] 4f 06 [2] 53 29 }

  condition:
    any of them
}