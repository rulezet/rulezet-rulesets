rule TTP_XOR_QUAD_CurrentVersionRun_d4a3 {
  strings:
    $key_d4a3 = { 87 cc [2] a3 c2 [2] 88 ee [2] a6 cc [2] b2 d7 [2] bd cd [2] a3 d0 [2] a1 d1 [2] ba d7 [2] a6 d0 [2] ba ff }

  condition:
    any of them
}