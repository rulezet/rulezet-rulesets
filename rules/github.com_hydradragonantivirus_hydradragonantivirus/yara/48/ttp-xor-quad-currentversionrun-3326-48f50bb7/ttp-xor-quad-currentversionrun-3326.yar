rule TTP_XOR_QUAD_CurrentVersionRun_3326 {
  strings:
    $key_3326 = { 60 49 [2] 44 47 [2] 6f 6b [2] 41 49 [2] 55 52 [2] 5a 48 [2] 44 55 [2] 46 54 [2] 5d 52 [2] 41 55 [2] 5d 7a }

  condition:
    any of them
}