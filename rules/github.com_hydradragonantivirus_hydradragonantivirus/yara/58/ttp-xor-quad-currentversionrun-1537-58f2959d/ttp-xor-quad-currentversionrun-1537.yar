rule TTP_XOR_QUAD_CurrentVersionRun_1537 {
  strings:
    $key_1537 = { 46 58 [2] 62 56 [2] 49 7a [2] 67 58 [2] 73 43 [2] 7c 59 [2] 62 44 [2] 60 45 [2] 7b 43 [2] 67 44 [2] 7b 6b }

  condition:
    any of them
}