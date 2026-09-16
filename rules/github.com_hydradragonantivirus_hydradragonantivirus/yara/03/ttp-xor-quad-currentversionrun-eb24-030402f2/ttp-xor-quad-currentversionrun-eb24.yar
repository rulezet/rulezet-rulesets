rule TTP_XOR_QUAD_CurrentVersionRun_eb24 {
  strings:
    $key_eb24 = { b8 4b [2] 9c 45 [2] b7 69 [2] 99 4b [2] 8d 50 [2] 82 4a [2] 9c 57 [2] 9e 56 [2] 85 50 [2] 99 57 [2] 85 78 }

  condition:
    any of them
}