rule TTP_XOR_MULT_DOSStub_e802 {
  strings:
    $key_e802 = { bc 6a [2] c8 72 [2] 8f 70 [2] c8 61 [2] 86 6d [2] 8a 67 [2] 9d 6c [2] 86 22 [2] bb }

  condition:
    any of them
}