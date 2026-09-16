rule TTP_XOR_QUAD_CurrentVersionRun_d6a3 {
  strings:
    $key_d6a3 = { 85 cc [2] a1 c2 [2] 8a ee [2] a4 cc [2] b0 d7 [2] bf cd [2] a1 d0 [2] a3 d1 [2] b8 d7 [2] a4 d0 [2] b8 ff }

  condition:
    any of them
}