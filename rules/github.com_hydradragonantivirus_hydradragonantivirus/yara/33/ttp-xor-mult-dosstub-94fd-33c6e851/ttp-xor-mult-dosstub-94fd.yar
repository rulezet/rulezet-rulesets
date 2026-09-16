rule TTP_XOR_MULT_DOSStub_94fd {
  strings:
    $key_94fd = { c0 95 [2] b4 8d [2] f3 8f [2] b4 9e [2] fa 92 [2] f6 98 [2] e1 93 [2] fa dd [2] c7 }

  condition:
    any of them
}