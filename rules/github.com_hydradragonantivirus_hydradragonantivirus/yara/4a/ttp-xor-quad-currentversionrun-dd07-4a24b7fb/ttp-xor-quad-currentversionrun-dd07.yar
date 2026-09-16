rule TTP_XOR_QUAD_CurrentVersionRun_dd07 {
  strings:
    $key_dd07 = { 8e 68 [2] aa 66 [2] 81 4a [2] af 68 [2] bb 73 [2] b4 69 [2] aa 74 [2] a8 75 [2] b3 73 [2] af 74 [2] b3 5b }

  condition:
    any of them
}