rule TTP_XOR_QUAD_CurrentVersionRun_dd4b {
  strings:
    $key_dd4b = { 8e 24 [2] aa 2a [2] 81 06 [2] af 24 [2] bb 3f [2] b4 25 [2] aa 38 [2] a8 39 [2] b3 3f [2] af 38 [2] b3 17 }

  condition:
    any of them
}