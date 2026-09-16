rule TTP_XOR_MULT_DOSStub_e7fd {
  strings:
    $key_e7fd = { b3 95 [2] c7 8d [2] 80 8f [2] c7 9e [2] 89 92 [2] 85 98 [2] 92 93 [2] 89 dd [2] b4 }

  condition:
    any of them
}