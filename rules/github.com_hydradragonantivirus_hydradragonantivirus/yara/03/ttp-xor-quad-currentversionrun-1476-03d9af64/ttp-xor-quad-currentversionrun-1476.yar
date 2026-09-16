rule TTP_XOR_QUAD_CurrentVersionRun_1476 {
  strings:
    $key_1476 = { 47 19 [2] 63 17 [2] 48 3b [2] 66 19 [2] 72 02 [2] 7d 18 [2] 63 05 [2] 61 04 [2] 7a 02 [2] 66 05 [2] 7a 2a }

  condition:
    any of them
}