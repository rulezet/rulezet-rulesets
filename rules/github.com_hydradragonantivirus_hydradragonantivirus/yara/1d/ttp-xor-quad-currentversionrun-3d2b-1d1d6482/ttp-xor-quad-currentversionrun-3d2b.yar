rule TTP_XOR_QUAD_CurrentVersionRun_3d2b {
  strings:
    $key_3d2b = { 6e 44 [2] 4a 4a [2] 61 66 [2] 4f 44 [2] 5b 5f [2] 54 45 [2] 4a 58 [2] 48 59 [2] 53 5f [2] 4f 58 [2] 53 77 }

  condition:
    any of them
}