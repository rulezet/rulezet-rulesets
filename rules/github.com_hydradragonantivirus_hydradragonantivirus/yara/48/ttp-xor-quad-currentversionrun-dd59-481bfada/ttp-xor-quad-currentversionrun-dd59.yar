rule TTP_XOR_QUAD_CurrentVersionRun_dd59 {
  strings:
    $key_dd59 = { 8e 36 [2] aa 38 [2] 81 14 [2] af 36 [2] bb 2d [2] b4 37 [2] aa 2a [2] a8 2b [2] b3 2d [2] af 2a [2] b3 05 }

  condition:
    any of them
}