rule TTP_XOR_MULT_DOSStub_54fd {
  strings:
    $key_54fd = { 00 95 [2] 74 8d [2] 33 8f [2] 74 9e [2] 3a 92 [2] 36 98 [2] 21 93 [2] 3a dd [2] 07 }

  condition:
    any of them
}