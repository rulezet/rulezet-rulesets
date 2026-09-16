rule TTP_XOR_QUAD_CurrentVersionRun_d779 {
  strings:
    $key_d779 = { 84 16 [2] a0 18 [2] 8b 34 [2] a5 16 [2] b1 0d [2] be 17 [2] a0 0a [2] a2 0b [2] b9 0d [2] a5 0a [2] b9 25 }

  condition:
    any of them
}