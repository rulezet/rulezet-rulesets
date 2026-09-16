rule TTP_XOR_QUAD_CurrentVersionRun_3d16 {
  strings:
    $key_3d16 = { 6e 79 [2] 4a 77 [2] 61 5b [2] 4f 79 [2] 5b 62 [2] 54 78 [2] 4a 65 [2] 48 64 [2] 53 62 [2] 4f 65 [2] 53 4a }

  condition:
    any of them
}