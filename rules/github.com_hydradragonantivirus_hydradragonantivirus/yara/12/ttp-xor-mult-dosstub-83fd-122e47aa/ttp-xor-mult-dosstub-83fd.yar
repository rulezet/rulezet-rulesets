rule TTP_XOR_MULT_DOSStub_83fd {
  strings:
    $key_83fd = { d7 95 [2] a3 8d [2] e4 8f [2] a3 9e [2] ed 92 [2] e1 98 [2] f6 93 [2] ed dd [2] d0 }

  condition:
    any of them
}