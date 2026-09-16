rule TTP_XOR_QUAD_CurrentVersionRun_3d04 {
  strings:
    $key_3d04 = { 6e 6b [2] 4a 65 [2] 61 49 [2] 4f 6b [2] 5b 70 [2] 54 6a [2] 4a 77 [2] 48 76 [2] 53 70 [2] 4f 77 [2] 53 58 }

  condition:
    any of them
}