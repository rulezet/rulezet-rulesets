rule TTP_XOR_QUAD_CurrentVersionRun_c648 {
  strings:
    $key_c648 = { 95 27 [2] b1 29 [2] 9a 05 [2] b4 27 [2] a0 3c [2] af 26 [2] b1 3b [2] b3 3a [2] a8 3c [2] b4 3b [2] a8 14 }

  condition:
    any of them
}