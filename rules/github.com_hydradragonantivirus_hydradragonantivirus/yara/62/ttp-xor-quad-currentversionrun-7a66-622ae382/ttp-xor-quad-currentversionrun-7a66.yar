rule TTP_XOR_QUAD_CurrentVersionRun_7a66 {
  strings:
    $key_7a66 = { 29 09 [2] 0d 07 [2] 26 2b [2] 08 09 [2] 1c 12 [2] 13 08 [2] 0d 15 [2] 0f 14 [2] 14 12 [2] 08 15 [2] 14 3a }

  condition:
    any of them
}