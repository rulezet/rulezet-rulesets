rule TTP_XOR_MULT_DOSStub_fad0 {
  strings:
    $key_fad0 = { ae b8 [2] da a0 [2] 9d a2 [2] da b3 [2] 94 bf [2] 98 b5 [2] 8f be [2] 94 f0 [2] a9 }

  condition:
    any of them
}