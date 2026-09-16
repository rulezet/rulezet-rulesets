rule TTP_XOR_QUAD_CurrentVersionRun_d7a3 {
  strings:
    $key_d7a3 = { 84 cc [2] a0 c2 [2] 8b ee [2] a5 cc [2] b1 d7 [2] be cd [2] a0 d0 [2] a2 d1 [2] b9 d7 [2] a5 d0 [2] b9 ff }

  condition:
    any of them
}