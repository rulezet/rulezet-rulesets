rule TTP_XOR_QUAD_CurrentVersionRun_d10b {
  strings:
    $key_d10b = { 82 64 [2] a6 6a [2] 8d 46 [2] a3 64 [2] b7 7f [2] b8 65 [2] a6 78 [2] a4 79 [2] bf 7f [2] a3 78 [2] bf 57 }

  condition:
    any of them
}