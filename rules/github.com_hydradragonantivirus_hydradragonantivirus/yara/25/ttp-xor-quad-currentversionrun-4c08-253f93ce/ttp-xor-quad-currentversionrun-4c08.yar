rule TTP_XOR_QUAD_CurrentVersionRun_4c08 {
  strings:
    $key_4c08 = { 1f 67 [2] 3b 69 [2] 10 45 [2] 3e 67 [2] 2a 7c [2] 25 66 [2] 3b 7b [2] 39 7a [2] 22 7c [2] 3e 7b [2] 22 54 }

  condition:
    any of them
}