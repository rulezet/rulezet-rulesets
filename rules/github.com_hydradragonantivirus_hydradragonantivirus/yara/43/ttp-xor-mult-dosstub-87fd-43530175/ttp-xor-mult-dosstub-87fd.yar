rule TTP_XOR_MULT_DOSStub_87fd {
  strings:
    $key_87fd = { d3 95 [2] a7 8d [2] e0 8f [2] a7 9e [2] e9 92 [2] e5 98 [2] f2 93 [2] e9 dd [2] d4 }

  condition:
    any of them
}