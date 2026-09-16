rule TTP_XOR_QUAD_CurrentVersionRun_1876 {
  strings:
    $key_1876 = { 4b 19 [2] 6f 17 [2] 44 3b [2] 6a 19 [2] 7e 02 [2] 71 18 [2] 6f 05 [2] 6d 04 [2] 76 02 [2] 6a 05 [2] 76 2a }

  condition:
    any of them
}