rule TTP_XOR_MULT_DOSStub_e856 {
  strings:
    $key_e856 = { bc 3e [2] c8 26 [2] 8f 24 [2] c8 35 [2] 86 39 [2] 8a 33 [2] 9d 38 [2] 86 76 [2] bb }

  condition:
    any of them
}