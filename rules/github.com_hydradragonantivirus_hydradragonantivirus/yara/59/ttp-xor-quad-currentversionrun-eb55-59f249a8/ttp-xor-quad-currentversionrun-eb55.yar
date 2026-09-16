rule TTP_XOR_QUAD_CurrentVersionRun_eb55 {
  strings:
    $key_eb55 = { b8 3a [2] 9c 34 [2] b7 18 [2] 99 3a [2] 8d 21 [2] 82 3b [2] 9c 26 [2] 9e 27 [2] 85 21 [2] 99 26 [2] 85 09 }

  condition:
    any of them
}