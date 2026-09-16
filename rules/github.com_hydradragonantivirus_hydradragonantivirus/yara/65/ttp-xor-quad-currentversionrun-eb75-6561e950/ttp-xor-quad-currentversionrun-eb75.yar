rule TTP_XOR_QUAD_CurrentVersionRun_eb75 {
  strings:
    $key_eb75 = { b8 1a [2] 9c 14 [2] b7 38 [2] 99 1a [2] 8d 01 [2] 82 1b [2] 9c 06 [2] 9e 07 [2] 85 01 [2] 99 06 [2] 85 29 }

  condition:
    any of them
}