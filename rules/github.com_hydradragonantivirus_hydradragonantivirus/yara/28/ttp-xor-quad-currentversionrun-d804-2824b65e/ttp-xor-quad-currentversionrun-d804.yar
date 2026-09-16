rule TTP_XOR_QUAD_CurrentVersionRun_d804 {
  strings:
    $key_d804 = { 8b 6b [2] af 65 [2] 84 49 [2] aa 6b [2] be 70 [2] b1 6a [2] af 77 [2] ad 76 [2] b6 70 [2] aa 77 [2] b6 58 }

  condition:
    any of them
}