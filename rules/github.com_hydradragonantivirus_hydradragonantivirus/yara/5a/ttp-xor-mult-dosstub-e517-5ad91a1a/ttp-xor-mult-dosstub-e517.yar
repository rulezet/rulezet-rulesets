rule TTP_XOR_MULT_DOSStub_e517 {
  strings:
    $key_e517 = { b1 7f [2] c5 67 [2] 82 65 [2] c5 74 [2] 8b 78 [2] 87 72 [2] 90 79 [2] 8b 37 [2] b6 }

  condition:
    any of them
}