rule TTP_XOR_QUAD_CurrentVersionRun_eb79 {
  strings:
    $key_eb79 = { b8 16 [2] 9c 18 [2] b7 34 [2] 99 16 [2] 8d 0d [2] 82 17 [2] 9c 0a [2] 9e 0b [2] 85 0d [2] 99 0a [2] 85 25 }

  condition:
    any of them
}