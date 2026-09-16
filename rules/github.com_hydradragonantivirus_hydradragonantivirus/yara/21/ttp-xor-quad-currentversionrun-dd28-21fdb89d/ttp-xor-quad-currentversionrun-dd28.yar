rule TTP_XOR_QUAD_CurrentVersionRun_dd28 {
  strings:
    $key_dd28 = { 8e 47 [2] aa 49 [2] 81 65 [2] af 47 [2] bb 5c [2] b4 46 [2] aa 5b [2] a8 5a [2] b3 5c [2] af 5b [2] b3 74 }

  condition:
    any of them
}