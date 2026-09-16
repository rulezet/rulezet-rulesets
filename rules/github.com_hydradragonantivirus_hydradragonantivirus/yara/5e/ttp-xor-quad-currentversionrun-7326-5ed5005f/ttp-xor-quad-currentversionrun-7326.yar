rule TTP_XOR_QUAD_CurrentVersionRun_7326 {
  strings:
    $key_7326 = { 20 49 [2] 04 47 [2] 2f 6b [2] 01 49 [2] 15 52 [2] 1a 48 [2] 04 55 [2] 06 54 [2] 1d 52 [2] 01 55 [2] 1d 7a }

  condition:
    any of them
}