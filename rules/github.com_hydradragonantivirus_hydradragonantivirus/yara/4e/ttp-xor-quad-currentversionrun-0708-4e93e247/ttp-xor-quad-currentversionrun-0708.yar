rule TTP_XOR_QUAD_CurrentVersionRun_0708 {
  strings:
    $key_0708 = { 54 67 [2] 70 69 [2] 5b 45 [2] 75 67 [2] 61 7c [2] 6e 66 [2] 70 7b [2] 72 7a [2] 69 7c [2] 75 7b [2] 69 54 }

  condition:
    any of them
}