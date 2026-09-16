rule TTP_XOR_QUAD_CurrentVersionRun_d12b {
  strings:
    $key_d12b = { 82 44 [2] a6 4a [2] 8d 66 [2] a3 44 [2] b7 5f [2] b8 45 [2] a6 58 [2] a4 59 [2] bf 5f [2] a3 58 [2] bf 77 }

  condition:
    any of them
}