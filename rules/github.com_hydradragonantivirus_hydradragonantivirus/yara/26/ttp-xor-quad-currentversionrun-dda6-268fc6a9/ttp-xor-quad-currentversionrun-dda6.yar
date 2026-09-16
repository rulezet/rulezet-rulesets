rule TTP_XOR_QUAD_CurrentVersionRun_dda6 {
  strings:
    $key_dda6 = { 8e c9 [2] aa c7 [2] 81 eb [2] af c9 [2] bb d2 [2] b4 c8 [2] aa d5 [2] a8 d4 [2] b3 d2 [2] af d5 [2] b3 fa }

  condition:
    any of them
}