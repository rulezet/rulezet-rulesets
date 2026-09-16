rule TTP_XOR_QUAD_CurrentVersionRun_ddfa {
  strings:
    $key_ddfa = { 8e 95 [2] aa 9b [2] 81 b7 [2] af 95 [2] bb 8e [2] b4 94 [2] aa 89 [2] a8 88 [2] b3 8e [2] af 89 [2] b3 a6 }

  condition:
    any of them
}