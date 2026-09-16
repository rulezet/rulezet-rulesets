rule TTP_XOR_QUAD_CurrentVersionRun_ede8 {
  strings:
    $key_ede8 = { be 87 [2] 9a 89 [2] b1 a5 [2] 9f 87 [2] 8b 9c [2] 84 86 [2] 9a 9b [2] 98 9a [2] 83 9c [2] 9f 9b [2] 83 b4 }

  condition:
    any of them
}