rule TTP_XOR_MULT_DOSStub_56fd {
  strings:
    $key_56fd = { 02 95 [2] 76 8d [2] 31 8f [2] 76 9e [2] 38 92 [2] 34 98 [2] 23 93 [2] 38 dd [2] 05 }

  condition:
    any of them
}