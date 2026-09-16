rule TTP_XOR_QUAD_CurrentVersionRun_eb68 {
  strings:
    $key_eb68 = { b8 07 [2] 9c 09 [2] b7 25 [2] 99 07 [2] 8d 1c [2] 82 06 [2] 9c 1b [2] 9e 1a [2] 85 1c [2] 99 1b [2] 85 34 }

  condition:
    any of them
}