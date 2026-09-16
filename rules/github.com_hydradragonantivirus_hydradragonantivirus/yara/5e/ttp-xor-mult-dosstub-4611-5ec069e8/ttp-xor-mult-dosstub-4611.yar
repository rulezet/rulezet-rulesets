rule TTP_XOR_MULT_DOSStub_4611 {
  strings:
    $key_4611 = { 12 79 [2] 66 61 [2] 21 63 [2] 66 72 [2] 28 7e [2] 24 74 [2] 33 7f [2] 28 31 [2] 15 }

  condition:
    any of them
}