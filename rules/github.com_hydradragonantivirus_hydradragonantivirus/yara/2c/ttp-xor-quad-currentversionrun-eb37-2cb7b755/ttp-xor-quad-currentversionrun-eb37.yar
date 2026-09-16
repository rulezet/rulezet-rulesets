rule TTP_XOR_QUAD_CurrentVersionRun_eb37 {
  strings:
    $key_eb37 = { b8 58 [2] 9c 56 [2] b7 7a [2] 99 58 [2] 8d 43 [2] 82 59 [2] 9c 44 [2] 9e 45 [2] 85 43 [2] 99 44 [2] 85 6b }

  condition:
    any of them
}