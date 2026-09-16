rule TTP_XOR_QUAD_CurrentVersionRun_c5b1 {
  strings:
    $key_c5b1 = { 96 de [2] b2 d0 [2] 99 fc [2] b7 de [2] a3 c5 [2] ac df [2] b2 c2 [2] b0 c3 [2] ab c5 [2] b7 c2 [2] ab ed }

  condition:
    any of them
}