rule TTP_XOR_QUAD_CurrentVersionRun_3d26 {
  strings:
    $key_3d26 = { 6e 49 [2] 4a 47 [2] 61 6b [2] 4f 49 [2] 5b 52 [2] 54 48 [2] 4a 55 [2] 48 54 [2] 53 52 [2] 4f 55 [2] 53 7a }

  condition:
    any of them
}