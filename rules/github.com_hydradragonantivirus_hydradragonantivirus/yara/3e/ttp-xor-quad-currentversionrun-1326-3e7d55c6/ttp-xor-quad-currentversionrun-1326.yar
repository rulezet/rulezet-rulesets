rule TTP_XOR_QUAD_CurrentVersionRun_1326 {
  strings:
    $key_1326 = { 40 49 [2] 64 47 [2] 4f 6b [2] 61 49 [2] 75 52 [2] 7a 48 [2] 64 55 [2] 66 54 [2] 7d 52 [2] 61 55 [2] 7d 7a }

  condition:
    any of them
}