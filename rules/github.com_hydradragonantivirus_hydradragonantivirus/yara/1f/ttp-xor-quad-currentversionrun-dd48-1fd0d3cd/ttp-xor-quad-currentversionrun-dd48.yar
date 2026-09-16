rule TTP_XOR_QUAD_CurrentVersionRun_dd48 {
  strings:
    $key_dd48 = { 8e 27 [2] aa 29 [2] 81 05 [2] af 27 [2] bb 3c [2] b4 26 [2] aa 3b [2] a8 3a [2] b3 3c [2] af 3b [2] b3 14 }

  condition:
    any of them
}