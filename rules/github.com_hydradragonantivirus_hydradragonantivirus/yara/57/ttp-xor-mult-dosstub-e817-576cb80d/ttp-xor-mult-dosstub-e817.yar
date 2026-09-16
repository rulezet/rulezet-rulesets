rule TTP_XOR_MULT_DOSStub_e817 {
  strings:
    $key_e817 = { bc 7f [2] c8 67 [2] 8f 65 [2] c8 74 [2] 86 78 [2] 8a 72 [2] 9d 79 [2] 86 37 [2] bb }

  condition:
    any of them
}