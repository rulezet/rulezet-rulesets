rule TTP_XOR_QUAD_CurrentVersionRun_cca6 {
  strings:
    $key_cca6 = { 9f c9 [2] bb c7 [2] 90 eb [2] be c9 [2] aa d2 [2] a5 c8 [2] bb d5 [2] b9 d4 [2] a2 d2 [2] be d5 [2] a2 fa }

  condition:
    any of them
}