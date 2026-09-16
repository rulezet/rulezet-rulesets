rule TTP_XOR_QUAD_CurrentVersionRun_d735 {
  strings:
    $key_d735 = { 84 5a [2] a0 54 [2] 8b 78 [2] a5 5a [2] b1 41 [2] be 5b [2] a0 46 [2] a2 47 [2] b9 41 [2] a5 46 [2] b9 69 }

  condition:
    any of them
}