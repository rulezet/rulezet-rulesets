rule TTP_XOR_QUAD_CurrentVersionRun_d629 {
  strings:
    $key_d629 = { 85 46 [2] a1 48 [2] 8a 64 [2] a4 46 [2] b0 5d [2] bf 47 [2] a1 5a [2] a3 5b [2] b8 5d [2] a4 5a [2] b8 75 }

  condition:
    any of them
}