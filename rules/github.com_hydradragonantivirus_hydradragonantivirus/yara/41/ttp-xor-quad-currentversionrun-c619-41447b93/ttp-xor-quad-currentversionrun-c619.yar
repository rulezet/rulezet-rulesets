rule TTP_XOR_QUAD_CurrentVersionRun_c619 {
  strings:
    $key_c619 = { 95 76 [2] b1 78 [2] 9a 54 [2] b4 76 [2] a0 6d [2] af 77 [2] b1 6a [2] b3 6b [2] a8 6d [2] b4 6a [2] a8 45 }

  condition:
    any of them
}