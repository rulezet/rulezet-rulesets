rule TTP_XOR_QUAD_CurrentVersionRun_c484 {
  strings:
    $key_c484 = { 97 eb [2] b3 e5 [2] 98 c9 [2] b6 eb [2] a2 f0 [2] ad ea [2] b3 f7 [2] b1 f6 [2] aa f0 [2] b6 f7 [2] aa d8 }

  condition:
    any of them
}