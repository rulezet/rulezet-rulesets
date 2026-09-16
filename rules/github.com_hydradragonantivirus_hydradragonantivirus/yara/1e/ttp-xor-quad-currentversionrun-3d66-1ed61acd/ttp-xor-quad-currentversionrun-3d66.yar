rule TTP_XOR_QUAD_CurrentVersionRun_3d66 {
  strings:
    $key_3d66 = { 6e 09 [2] 4a 07 [2] 61 2b [2] 4f 09 [2] 5b 12 [2] 54 08 [2] 4a 15 [2] 48 14 [2] 53 12 [2] 4f 15 [2] 53 3a }

  condition:
    any of them
}