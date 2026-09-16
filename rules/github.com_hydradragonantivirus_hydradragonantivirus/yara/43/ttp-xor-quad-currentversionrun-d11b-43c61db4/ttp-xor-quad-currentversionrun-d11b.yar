rule TTP_XOR_QUAD_CurrentVersionRun_d11b {
  strings:
    $key_d11b = { 82 74 [2] a6 7a [2] 8d 56 [2] a3 74 [2] b7 6f [2] b8 75 [2] a6 68 [2] a4 69 [2] bf 6f [2] a3 68 [2] bf 47 }

  condition:
    any of them
}