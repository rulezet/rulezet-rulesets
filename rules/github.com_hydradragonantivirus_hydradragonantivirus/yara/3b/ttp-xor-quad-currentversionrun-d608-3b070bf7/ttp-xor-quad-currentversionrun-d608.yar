rule TTP_XOR_QUAD_CurrentVersionRun_d608 {
  strings:
    $key_d608 = { 85 67 [2] a1 69 [2] 8a 45 [2] a4 67 [2] b0 7c [2] bf 66 [2] a1 7b [2] a3 7a [2] b8 7c [2] a4 7b [2] b8 54 }

  condition:
    any of them
}