rule TTP_XOR_QUAD_CurrentVersionRun_3d19 {
  strings:
    $key_3d19 = { 6e 76 [2] 4a 78 [2] 61 54 [2] 4f 76 [2] 5b 6d [2] 54 77 [2] 4a 6a [2] 48 6b [2] 53 6d [2] 4f 6a [2] 53 45 }

  condition:
    any of them
}