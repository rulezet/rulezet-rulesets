rule TTP_XOR_MULT_DOSStub_64fd {
  strings:
    $key_64fd = { 30 95 [2] 44 8d [2] 03 8f [2] 44 9e [2] 0a 92 [2] 06 98 [2] 11 93 [2] 0a dd [2] 37 }

  condition:
    any of them
}