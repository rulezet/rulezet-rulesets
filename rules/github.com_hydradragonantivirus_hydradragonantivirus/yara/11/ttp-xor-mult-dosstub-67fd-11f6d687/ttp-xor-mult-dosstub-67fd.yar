rule TTP_XOR_MULT_DOSStub_67fd {
  strings:
    $key_67fd = { 33 95 [2] 47 8d [2] 00 8f [2] 47 9e [2] 09 92 [2] 05 98 [2] 12 93 [2] 09 dd [2] 34 }

  condition:
    any of them
}