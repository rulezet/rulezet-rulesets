rule TTP_XOR_MULT_DOSStub_e8f0 {
  strings:
    $key_e8f0 = { bc 98 [2] c8 80 [2] 8f 82 [2] c8 93 [2] 86 9f [2] 8a 95 [2] 9d 9e [2] 86 d0 [2] bb }

  condition:
    any of them
}