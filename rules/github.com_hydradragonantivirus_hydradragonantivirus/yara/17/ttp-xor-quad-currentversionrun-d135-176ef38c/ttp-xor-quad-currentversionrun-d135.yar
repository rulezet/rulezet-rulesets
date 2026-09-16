rule TTP_XOR_QUAD_CurrentVersionRun_d135 {
  strings:
    $key_d135 = { 82 5a [2] a6 54 [2] 8d 78 [2] a3 5a [2] b7 41 [2] b8 5b [2] a6 46 [2] a4 47 [2] bf 41 [2] a3 46 [2] bf 69 }

  condition:
    any of them
}