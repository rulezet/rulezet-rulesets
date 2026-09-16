rule TTP_XOR_QUAD_CurrentVersionRun_dd09 {
  strings:
    $key_dd09 = { 8e 66 [2] aa 68 [2] 81 44 [2] af 66 [2] bb 7d [2] b4 67 [2] aa 7a [2] a8 7b [2] b3 7d [2] af 7a [2] b3 55 }

  condition:
    any of them
}