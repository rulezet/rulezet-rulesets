rule TTP_XOR_QUAD_CurrentVersionRun_2578 {
  strings:
    $key_2578 = { 76 17 [2] 52 19 [2] 79 35 [2] 57 17 [2] 43 0c [2] 4c 16 [2] 52 0b [2] 50 0a [2] 4b 0c [2] 57 0b [2] 4b 24 }

  condition:
    any of them
}