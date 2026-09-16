rule TTP_XOR_QUAD_CurrentVersionRun_dd75 {
  strings:
    $key_dd75 = { 8e 1a [2] aa 14 [2] 81 38 [2] af 1a [2] bb 01 [2] b4 1b [2] aa 06 [2] a8 07 [2] b3 01 [2] af 06 [2] b3 29 }

  condition:
    any of them
}