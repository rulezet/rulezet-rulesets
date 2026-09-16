rule TTP_XOR_QUAD_CurrentVersionRun_ccad {
  strings:
    $key_ccad = { 9f c2 [2] bb cc [2] 90 e0 [2] be c2 [2] aa d9 [2] a5 c3 [2] bb de [2] b9 df [2] a2 d9 [2] be de [2] a2 f1 }

  condition:
    any of them
}