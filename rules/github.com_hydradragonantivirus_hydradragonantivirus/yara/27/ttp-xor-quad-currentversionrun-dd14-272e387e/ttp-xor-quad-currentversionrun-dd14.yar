rule TTP_XOR_QUAD_CurrentVersionRun_dd14 {
  strings:
    $key_dd14 = { 8e 7b [2] aa 75 [2] 81 59 [2] af 7b [2] bb 60 [2] b4 7a [2] aa 67 [2] a8 66 [2] b3 60 [2] af 67 [2] b3 48 }

  condition:
    any of them
}