rule TTP_XOR_QUAD_CurrentVersionRun_d13b {
  strings:
    $key_d13b = { 82 54 [2] a6 5a [2] 8d 76 [2] a3 54 [2] b7 4f [2] b8 55 [2] a6 48 [2] a4 49 [2] bf 4f [2] a3 48 [2] bf 67 }

  condition:
    any of them
}