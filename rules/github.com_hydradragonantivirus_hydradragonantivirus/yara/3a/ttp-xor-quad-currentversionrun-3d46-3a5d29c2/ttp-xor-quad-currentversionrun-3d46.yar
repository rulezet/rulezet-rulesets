rule TTP_XOR_QUAD_CurrentVersionRun_3d46 {
  strings:
    $key_3d46 = { 6e 29 [2] 4a 27 [2] 61 0b [2] 4f 29 [2] 5b 32 [2] 54 28 [2] 4a 35 [2] 48 34 [2] 53 32 [2] 4f 35 [2] 53 1a }

  condition:
    any of them
}