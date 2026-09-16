rule TTP_XOR_MULT_DOSStub_35fd {
  strings:
    $key_35fd = { 61 95 [2] 15 8d [2] 52 8f [2] 15 9e [2] 5b 92 [2] 57 98 [2] 40 93 [2] 5b dd [2] 66 }

  condition:
    any of them
}