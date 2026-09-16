rule TTP_XOR_QUAD_CurrentVersionRun_6708 {
  strings:
    $key_6708 = { 34 67 [2] 10 69 [2] 3b 45 [2] 15 67 [2] 01 7c [2] 0e 66 [2] 10 7b [2] 12 7a [2] 09 7c [2] 15 7b [2] 09 54 }

  condition:
    any of them
}