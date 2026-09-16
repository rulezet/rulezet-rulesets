rule TTP_XOR_MULT_DOSStub_14fd {
  strings:
    $key_14fd = { 40 95 [2] 34 8d [2] 73 8f [2] 34 9e [2] 7a 92 [2] 76 98 [2] 61 93 [2] 7a dd [2] 47 }

  condition:
    any of them
}