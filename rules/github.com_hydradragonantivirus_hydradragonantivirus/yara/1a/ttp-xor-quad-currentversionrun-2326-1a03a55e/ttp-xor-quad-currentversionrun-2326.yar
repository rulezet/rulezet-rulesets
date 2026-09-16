rule TTP_XOR_QUAD_CurrentVersionRun_2326 {
  strings:
    $key_2326 = { 70 49 [2] 54 47 [2] 7f 6b [2] 51 49 [2] 45 52 [2] 4a 48 [2] 54 55 [2] 56 54 [2] 4d 52 [2] 51 55 [2] 4d 7a }

  condition:
    any of them
}