rule TTP_XOR_QUAD_CurrentVersionRun_dde9 {
  strings:
    $key_dde9 = { 8e 86 [2] aa 88 [2] 81 a4 [2] af 86 [2] bb 9d [2] b4 87 [2] aa 9a [2] a8 9b [2] b3 9d [2] af 9a [2] b3 b5 }

  condition:
    any of them
}