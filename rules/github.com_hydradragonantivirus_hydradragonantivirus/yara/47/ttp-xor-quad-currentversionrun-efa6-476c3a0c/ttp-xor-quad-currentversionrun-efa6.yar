rule TTP_XOR_QUAD_CurrentVersionRun_efa6 {
  strings:
    $key_efa6 = { bc c9 [2] 98 c7 [2] b3 eb [2] 9d c9 [2] 89 d2 [2] 86 c8 [2] 98 d5 [2] 9a d4 [2] 81 d2 [2] 9d d5 [2] 81 fa }

  condition:
    any of them
}