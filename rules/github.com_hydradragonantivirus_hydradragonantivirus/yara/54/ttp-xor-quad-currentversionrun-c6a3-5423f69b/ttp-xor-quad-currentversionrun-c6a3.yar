rule TTP_XOR_QUAD_CurrentVersionRun_c6a3 {
  strings:
    $key_c6a3 = { 95 cc [2] b1 c2 [2] 9a ee [2] b4 cc [2] a0 d7 [2] af cd [2] b1 d0 [2] b3 d1 [2] a8 d7 [2] b4 d0 [2] a8 ff }

  condition:
    any of them
}