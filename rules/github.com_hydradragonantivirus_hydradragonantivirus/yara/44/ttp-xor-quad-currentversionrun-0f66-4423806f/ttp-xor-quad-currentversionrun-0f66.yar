rule TTP_XOR_QUAD_CurrentVersionRun_0f66 {
  strings:
    $key_0f66 = { 5c 09 [2] 78 07 [2] 53 2b [2] 7d 09 [2] 69 12 [2] 66 08 [2] 78 15 [2] 7a 14 [2] 61 12 [2] 7d 15 [2] 61 3a }

  condition:
    any of them
}