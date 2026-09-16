rule TTP_XOR_MULT_DOSStub_d6fd {
  strings:
    $key_d6fd = { 82 95 [2] f6 8d [2] b1 8f [2] f6 9e [2] b8 92 [2] b4 98 [2] a3 93 [2] b8 dd [2] 85 }

  condition:
    any of them
}