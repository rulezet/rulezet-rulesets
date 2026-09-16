rule TTP_XOR_QUAD_CurrentVersionRun_3d77 {
  strings:
    $key_3d77 = { 6e 18 [2] 4a 16 [2] 61 3a [2] 4f 18 [2] 5b 03 [2] 54 19 [2] 4a 04 [2] 48 05 [2] 53 03 [2] 4f 04 [2] 53 2b }

  condition:
    any of them
}