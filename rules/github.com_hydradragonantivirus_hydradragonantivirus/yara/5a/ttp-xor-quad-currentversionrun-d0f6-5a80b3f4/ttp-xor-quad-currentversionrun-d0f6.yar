rule TTP_XOR_QUAD_CurrentVersionRun_d0f6 {
  strings:
    $key_d0f6 = { 83 99 [2] a7 97 [2] 8c bb [2] a2 99 [2] b6 82 [2] b9 98 [2] a7 85 [2] a5 84 [2] be 82 [2] a2 85 [2] be aa }

  condition:
    any of them
}