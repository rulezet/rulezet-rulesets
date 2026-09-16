rule TTP_XOR_MULT_DOSStub_74fd {
  strings:
    $key_74fd = { 20 95 [2] 54 8d [2] 13 8f [2] 54 9e [2] 1a 92 [2] 16 98 [2] 01 93 [2] 1a dd [2] 27 }

  condition:
    any of them
}