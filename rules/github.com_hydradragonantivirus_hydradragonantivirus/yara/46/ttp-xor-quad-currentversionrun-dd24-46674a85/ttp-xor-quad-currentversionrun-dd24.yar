rule TTP_XOR_QUAD_CurrentVersionRun_dd24 {
  strings:
    $key_dd24 = { 8e 4b [2] aa 45 [2] 81 69 [2] af 4b [2] bb 50 [2] b4 4a [2] aa 57 [2] a8 56 [2] b3 50 [2] af 57 [2] b3 78 }

  condition:
    any of them
}