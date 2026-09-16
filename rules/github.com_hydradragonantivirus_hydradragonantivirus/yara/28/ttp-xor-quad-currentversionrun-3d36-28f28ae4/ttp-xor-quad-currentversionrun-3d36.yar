rule TTP_XOR_QUAD_CurrentVersionRun_3d36 {
  strings:
    $key_3d36 = { 6e 59 [2] 4a 57 [2] 61 7b [2] 4f 59 [2] 5b 42 [2] 54 58 [2] 4a 45 [2] 48 44 [2] 53 42 [2] 4f 45 [2] 53 6a }

  condition:
    any of them
}