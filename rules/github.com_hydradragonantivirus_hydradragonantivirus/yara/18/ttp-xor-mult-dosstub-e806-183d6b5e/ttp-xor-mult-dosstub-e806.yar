rule TTP_XOR_MULT_DOSStub_e806 {
  strings:
    $key_e806 = { bc 6e [2] c8 76 [2] 8f 74 [2] c8 65 [2] 86 69 [2] 8a 63 [2] 9d 68 [2] 86 26 [2] bb }

  condition:
    any of them
}