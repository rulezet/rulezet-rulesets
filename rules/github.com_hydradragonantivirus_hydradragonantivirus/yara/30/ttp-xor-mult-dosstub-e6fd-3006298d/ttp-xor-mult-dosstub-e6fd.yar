rule TTP_XOR_MULT_DOSStub_e6fd {
  strings:
    $key_e6fd = { b2 95 [2] c6 8d [2] 81 8f [2] c6 9e [2] 88 92 [2] 84 98 [2] 93 93 [2] 88 dd [2] b5 }

  condition:
    any of them
}