rule TTP_XOR_MULT_DOSStub_33fd {
  strings:
    $key_33fd = { 67 95 [2] 13 8d [2] 54 8f [2] 13 9e [2] 5d 92 [2] 51 98 [2] 46 93 [2] 5d dd [2] 60 }

  condition:
    any of them
}