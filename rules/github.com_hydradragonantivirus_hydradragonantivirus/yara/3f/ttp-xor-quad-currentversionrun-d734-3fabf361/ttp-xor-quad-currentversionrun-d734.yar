rule TTP_XOR_QUAD_CurrentVersionRun_d734 {
  strings:
    $key_d734 = { 84 5b [2] a0 55 [2] 8b 79 [2] a5 5b [2] b1 40 [2] be 5a [2] a0 47 [2] a2 46 [2] b9 40 [2] a5 47 [2] b9 68 }

  condition:
    any of them
}