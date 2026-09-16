rule TTP_XOR_QUAD_CurrentVersionRun_1466 {
  strings:
    $key_1466 = { 47 09 [2] 63 07 [2] 48 2b [2] 66 09 [2] 72 12 [2] 7d 08 [2] 63 15 [2] 61 14 [2] 7a 12 [2] 66 15 [2] 7a 3a }

  condition:
    any of them
}