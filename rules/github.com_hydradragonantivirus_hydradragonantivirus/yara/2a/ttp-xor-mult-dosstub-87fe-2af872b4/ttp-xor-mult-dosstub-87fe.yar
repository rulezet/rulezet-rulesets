rule TTP_XOR_MULT_DOSStub_87fe {
  strings:
    $key_87fe = { d3 96 [2] a7 8e [2] e0 8c [2] a7 9d [2] e9 91 [2] e5 9b [2] f2 90 [2] e9 de [2] d4 }

  condition:
    any of them
}