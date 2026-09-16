rule TTP_XOR_MULT_DOSStub_fad1 {
  strings:
    $key_fad1 = { ae b9 [2] da a1 [2] 9d a3 [2] da b2 [2] 94 be [2] 98 b4 [2] 8f bf [2] 94 f1 [2] a9 }

  condition:
    any of them
}