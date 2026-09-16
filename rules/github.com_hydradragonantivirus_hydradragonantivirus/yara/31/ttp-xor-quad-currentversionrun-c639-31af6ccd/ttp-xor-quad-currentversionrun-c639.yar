rule TTP_XOR_QUAD_CurrentVersionRun_c639 {
  strings:
    $key_c639 = { 95 56 [2] b1 58 [2] 9a 74 [2] b4 56 [2] a0 4d [2] af 57 [2] b1 4a [2] b3 4b [2] a8 4d [2] b4 4a [2] a8 65 }

  condition:
    any of them
}