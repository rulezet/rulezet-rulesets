rule TTP_XOR_QUAD_CurrentVersionRun_1508 {
  strings:
    $key_1508 = { 46 67 [2] 62 69 [2] 49 45 [2] 67 67 [2] 73 7c [2] 7c 66 [2] 62 7b [2] 60 7a [2] 7b 7c [2] 67 7b [2] 7b 54 }

  condition:
    any of them
}