rule TTP_XOR_QUAD_CurrentVersionRun_0176 {
  strings:
    $key_0176 = { 52 19 [2] 76 17 [2] 5d 3b [2] 73 19 [2] 67 02 [2] 68 18 [2] 76 05 [2] 74 04 [2] 6f 02 [2] 73 05 [2] 6f 2a }

  condition:
    any of them
}