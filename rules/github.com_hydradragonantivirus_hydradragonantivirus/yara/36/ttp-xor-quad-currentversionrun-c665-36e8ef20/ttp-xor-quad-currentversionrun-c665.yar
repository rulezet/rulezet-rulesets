rule TTP_XOR_QUAD_CurrentVersionRun_c665 {
  strings:
    $key_c665 = { 95 0a [2] b1 04 [2] 9a 28 [2] b4 0a [2] a0 11 [2] af 0b [2] b1 16 [2] b3 17 [2] a8 11 [2] b4 16 [2] a8 39 }

  condition:
    any of them
}