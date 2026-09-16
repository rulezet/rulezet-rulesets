rule TTP_XOR_QUAD_CurrentVersionRun_dd06 {
  strings:
    $key_dd06 = { 8e 69 [2] aa 67 [2] 81 4b [2] af 69 [2] bb 72 [2] b4 68 [2] aa 75 [2] a8 74 [2] b3 72 [2] af 75 [2] b3 5a }

  condition:
    any of them
}