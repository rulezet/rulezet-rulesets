rule TTP_XOR_QUAD_CurrentVersionRun_d744 {
  strings:
    $key_d744 = { 84 2b [2] a0 25 [2] 8b 09 [2] a5 2b [2] b1 30 [2] be 2a [2] a0 37 [2] a2 36 [2] b9 30 [2] a5 37 [2] b9 18 }

  condition:
    any of them
}