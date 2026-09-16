rule TTP_XOR_QUAD_CurrentVersionRun_d714 {
  strings:
    $key_d714 = { 84 7b [2] a0 75 [2] 8b 59 [2] a5 7b [2] b1 60 [2] be 7a [2] a0 67 [2] a2 66 [2] b9 60 [2] a5 67 [2] b9 48 }

  condition:
    any of them
}