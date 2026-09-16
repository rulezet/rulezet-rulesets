rule TTP_XOR_QUAD_CurrentVersionRun_dd36 {
  strings:
    $key_dd36 = { 8e 59 [2] aa 57 [2] 81 7b [2] af 59 [2] bb 42 [2] b4 58 [2] aa 45 [2] a8 44 [2] b3 42 [2] af 45 [2] b3 6a }

  condition:
    any of them
}