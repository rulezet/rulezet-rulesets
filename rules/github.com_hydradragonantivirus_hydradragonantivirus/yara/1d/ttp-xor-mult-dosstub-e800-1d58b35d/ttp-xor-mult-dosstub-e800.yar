rule TTP_XOR_MULT_DOSStub_e800 {
  strings:
    $key_e800 = { bc 68 [2] c8 70 [2] 8f 72 [2] c8 63 [2] 86 6f [2] 8a 65 [2] 9d 6e [2] 86 20 [2] bb }

  condition:
    any of them
}