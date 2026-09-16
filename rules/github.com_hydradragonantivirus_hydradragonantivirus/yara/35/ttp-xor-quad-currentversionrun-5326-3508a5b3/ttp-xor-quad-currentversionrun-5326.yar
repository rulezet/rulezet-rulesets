rule TTP_XOR_QUAD_CurrentVersionRun_5326 {
  strings:
    $key_5326 = { 00 49 [2] 24 47 [2] 0f 6b [2] 21 49 [2] 35 52 [2] 3a 48 [2] 24 55 [2] 26 54 [2] 3d 52 [2] 21 55 [2] 3d 7a }

  condition:
    any of them
}