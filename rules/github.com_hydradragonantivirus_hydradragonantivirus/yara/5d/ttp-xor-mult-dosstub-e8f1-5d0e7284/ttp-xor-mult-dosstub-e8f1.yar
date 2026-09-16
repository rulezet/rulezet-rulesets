rule TTP_XOR_MULT_DOSStub_e8f1 {
  strings:
    $key_e8f1 = { bc 99 [2] c8 81 [2] 8f 83 [2] c8 92 [2] 86 9e [2] 8a 94 [2] 9d 9f [2] 86 d1 [2] bb }

  condition:
    any of them
}