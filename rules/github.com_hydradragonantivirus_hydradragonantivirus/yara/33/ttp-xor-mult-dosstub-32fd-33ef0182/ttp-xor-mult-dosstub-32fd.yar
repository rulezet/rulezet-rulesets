rule TTP_XOR_MULT_DOSStub_32fd {
  strings:
    $key_32fd = { 66 95 [2] 12 8d [2] 55 8f [2] 12 9e [2] 5c 92 [2] 50 98 [2] 47 93 [2] 5c dd [2] 61 }

  condition:
    any of them
}