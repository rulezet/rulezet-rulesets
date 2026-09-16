rule TTP_XOR_MULT_DOSStub_47fd {
  strings:
    $key_47fd = { 13 95 [2] 67 8d [2] 20 8f [2] 67 9e [2] 29 92 [2] 25 98 [2] 32 93 [2] 29 dd [2] 14 }

  condition:
    any of them
}