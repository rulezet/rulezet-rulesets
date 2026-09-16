rule TTP_XOR_MULT_DOSStub_97fd {
  strings:
    $key_97fd = { c3 95 [2] b7 8d [2] f0 8f [2] b7 9e [2] f9 92 [2] f5 98 [2] e2 93 [2] f9 dd [2] c4 }

  condition:
    any of them
}