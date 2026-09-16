rule TTP_XOR_QUAD_CurrentVersionRun_c7a3 {
  strings:
    $key_c7a3 = { 94 cc [2] b0 c2 [2] 9b ee [2] b5 cc [2] a1 d7 [2] ae cd [2] b0 d0 [2] b2 d1 [2] a9 d7 [2] b5 d0 [2] a9 ff }

  condition:
    any of them
}