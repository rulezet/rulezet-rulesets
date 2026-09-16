rule TTP_XOR_MULT_DOSStub_e8e0 {
  strings:
    $key_e8e0 = { bc 88 [2] c8 90 [2] 8f 92 [2] c8 83 [2] 86 8f [2] 8a 85 [2] 9d 8e [2] 86 c0 [2] bb }

  condition:
    any of them
}