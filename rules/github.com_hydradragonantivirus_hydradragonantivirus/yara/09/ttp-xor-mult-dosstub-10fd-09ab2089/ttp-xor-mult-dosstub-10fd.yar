rule TTP_XOR_MULT_DOSStub_10fd {
  strings:
    $key_10fd = { 44 95 [2] 30 8d [2] 77 8f [2] 30 9e [2] 7e 92 [2] 72 98 [2] 65 93 [2] 7e dd [2] 43 }

  condition:
    any of them
}