rule TTP_XOR_MULT_DOSStub_d7fd {
  strings:
    $key_d7fd = { 83 95 [2] f7 8d [2] b0 8f [2] f7 9e [2] b9 92 [2] b5 98 [2] a2 93 [2] b9 dd [2] 84 }

  condition:
    any of them
}