rule TTP_XOR_QUAD_CurrentVersionRun_4876 {
  strings:
    $key_4876 = { 1b 19 [2] 3f 17 [2] 14 3b [2] 3a 19 [2] 2e 02 [2] 21 18 [2] 3f 05 [2] 3d 04 [2] 26 02 [2] 3a 05 [2] 26 2a }

  condition:
    any of them
}