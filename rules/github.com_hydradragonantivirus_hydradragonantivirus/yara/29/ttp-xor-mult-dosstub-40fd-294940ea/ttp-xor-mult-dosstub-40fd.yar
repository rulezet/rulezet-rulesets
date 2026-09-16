rule TTP_XOR_MULT_DOSStub_40fd {
  strings:
    $key_40fd = { 14 95 [2] 60 8d [2] 27 8f [2] 60 9e [2] 2e 92 [2] 22 98 [2] 35 93 [2] 2e dd [2] 13 }

  condition:
    any of them
}