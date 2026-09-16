rule TTP_XOR_QUAD_CurrentVersionRun_4908 {
  strings:
    $key_4908 = { 1a 67 [2] 3e 69 [2] 15 45 [2] 3b 67 [2] 2f 7c [2] 20 66 [2] 3e 7b [2] 3c 7a [2] 27 7c [2] 3b 7b [2] 27 54 }

  condition:
    any of them
}