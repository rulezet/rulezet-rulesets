rule TTP_XOR_QUAD_CurrentVersionRun_ddf4 {
  strings:
    $key_ddf4 = { 8e 9b [2] aa 95 [2] 81 b9 [2] af 9b [2] bb 80 [2] b4 9a [2] aa 87 [2] a8 86 [2] b3 80 [2] af 87 [2] b3 a8 }

  condition:
    any of them
}