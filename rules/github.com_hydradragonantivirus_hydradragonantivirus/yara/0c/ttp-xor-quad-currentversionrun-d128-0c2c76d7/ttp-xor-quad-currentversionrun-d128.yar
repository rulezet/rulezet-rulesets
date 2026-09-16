rule TTP_XOR_QUAD_CurrentVersionRun_d128 {
  strings:
    $key_d128 = { 82 47 [2] a6 49 [2] 8d 65 [2] a3 47 [2] b7 5c [2] b8 46 [2] a6 5b [2] a4 5a [2] bf 5c [2] a3 5b [2] bf 74 }

  condition:
    any of them
}