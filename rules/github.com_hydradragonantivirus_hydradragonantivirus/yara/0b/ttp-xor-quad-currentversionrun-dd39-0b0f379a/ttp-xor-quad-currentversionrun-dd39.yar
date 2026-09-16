rule TTP_XOR_QUAD_CurrentVersionRun_dd39 {
  strings:
    $key_dd39 = { 8e 56 [2] aa 58 [2] 81 74 [2] af 56 [2] bb 4d [2] b4 57 [2] aa 4a [2] a8 4b [2] b3 4d [2] af 4a [2] b3 65 }

  condition:
    any of them
}