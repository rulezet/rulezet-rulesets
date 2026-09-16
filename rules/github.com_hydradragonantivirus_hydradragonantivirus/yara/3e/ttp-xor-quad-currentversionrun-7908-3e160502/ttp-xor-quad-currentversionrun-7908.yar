rule TTP_XOR_QUAD_CurrentVersionRun_7908 {
  strings:
    $key_7908 = { 2a 67 [2] 0e 69 [2] 25 45 [2] 0b 67 [2] 1f 7c [2] 10 66 [2] 0e 7b [2] 0c 7a [2] 17 7c [2] 0b 7b [2] 17 54 }

  condition:
    any of them
}