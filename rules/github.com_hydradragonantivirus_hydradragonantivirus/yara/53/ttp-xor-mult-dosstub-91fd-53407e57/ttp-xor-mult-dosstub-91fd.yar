rule TTP_XOR_MULT_DOSStub_91fd {
  strings:
    $key_91fd = { c5 95 [2] b1 8d [2] f6 8f [2] b1 9e [2] ff 92 [2] f3 98 [2] e4 93 [2] ff dd [2] c2 }

  condition:
    any of them
}