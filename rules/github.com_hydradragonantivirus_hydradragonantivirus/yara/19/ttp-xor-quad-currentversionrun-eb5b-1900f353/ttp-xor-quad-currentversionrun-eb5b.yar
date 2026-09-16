rule TTP_XOR_QUAD_CurrentVersionRun_eb5b {
  strings:
    $key_eb5b = { b8 34 [2] 9c 3a [2] b7 16 [2] 99 34 [2] 8d 2f [2] 82 35 [2] 9c 28 [2] 9e 29 [2] 85 2f [2] 99 28 [2] 85 07 }

  condition:
    any of them
}