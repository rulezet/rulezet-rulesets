rule TTP_XOR_MULT_DOSStub_70fd {
  strings:
    $key_70fd = { 24 95 [2] 50 8d [2] 17 8f [2] 50 9e [2] 1e 92 [2] 12 98 [2] 05 93 [2] 1e dd [2] 23 }

  condition:
    any of them
}