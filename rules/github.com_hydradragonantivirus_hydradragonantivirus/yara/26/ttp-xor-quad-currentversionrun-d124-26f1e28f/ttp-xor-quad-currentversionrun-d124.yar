rule TTP_XOR_QUAD_CurrentVersionRun_d124 {
  strings:
    $key_d124 = { 82 4b [2] a6 45 [2] 8d 69 [2] a3 4b [2] b7 50 [2] b8 4a [2] a6 57 [2] a4 56 [2] bf 50 [2] a3 57 [2] bf 78 }

  condition:
    any of them
}