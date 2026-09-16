rule TTP_XOR_MULT_DOSStub_96fd {
  strings:
    $key_96fd = { c2 95 [2] b6 8d [2] f1 8f [2] b6 9e [2] f8 92 [2] f4 98 [2] e3 93 [2] f8 dd [2] c5 }

  condition:
    any of them
}