rule TTP_XOR_QUAD_CurrentVersionRun_d624 {
  strings:
    $key_d624 = { 85 4b [2] a1 45 [2] 8a 69 [2] a4 4b [2] b0 50 [2] bf 4a [2] a1 57 [2] a3 56 [2] b8 50 [2] a4 57 [2] b8 78 }

  condition:
    any of them
}