rule TTP_XOR_QUAD_CurrentVersionRun_dde8 {
  strings:
    $key_dde8 = { 8e 87 [2] aa 89 [2] 81 a5 [2] af 87 [2] bb 9c [2] b4 86 [2] aa 9b [2] a8 9a [2] b3 9c [2] af 9b [2] b3 b4 }

  condition:
    any of them
}