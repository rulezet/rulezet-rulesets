rule TTP_XOR_QUAD_CurrentVersionRun_c624 {
  strings:
    $key_c624 = { 95 4b [2] b1 45 [2] 9a 69 [2] b4 4b [2] a0 50 [2] af 4a [2] b1 57 [2] b3 56 [2] a8 50 [2] b4 57 [2] a8 78 }

  condition:
    any of them
}