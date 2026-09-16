rule TTP_XOR_QUAD_CurrentVersionRun_0f76 {
  strings:
    $key_0f76 = { 5c 19 [2] 78 17 [2] 53 3b [2] 7d 19 [2] 69 02 [2] 66 18 [2] 78 05 [2] 7a 04 [2] 61 02 [2] 7d 05 [2] 61 2a }

  condition:
    any of them
}