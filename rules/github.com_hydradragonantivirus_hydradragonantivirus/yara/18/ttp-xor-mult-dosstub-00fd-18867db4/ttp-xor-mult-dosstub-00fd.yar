rule TTP_XOR_MULT_DOSStub_00fd {
  strings:
    $key_00fd = { 54 95 [2] 20 8d [2] 67 8f [2] 20 9e [2] 6e 92 [2] 62 98 [2] 75 93 [2] 6e dd [2] 53 }

  condition:
    any of them
}