rule TTP_XOR_QUAD_CurrentVersionRun_cca5 {
  strings:
    $key_cca5 = { 9f ca [2] bb c4 [2] 90 e8 [2] be ca [2] aa d1 [2] a5 cb [2] bb d6 [2] b9 d7 [2] a2 d1 [2] be d6 [2] a2 f9 }

  condition:
    any of them
}