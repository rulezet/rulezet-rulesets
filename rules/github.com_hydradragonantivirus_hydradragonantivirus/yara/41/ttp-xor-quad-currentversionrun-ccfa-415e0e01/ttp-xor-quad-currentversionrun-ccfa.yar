rule TTP_XOR_QUAD_CurrentVersionRun_ccfa {
  strings:
    $key_ccfa = { 9f 95 [2] bb 9b [2] 90 b7 [2] be 95 [2] aa 8e [2] a5 94 [2] bb 89 [2] b9 88 [2] a2 8e [2] be 89 [2] a2 a6 }

  condition:
    any of them
}