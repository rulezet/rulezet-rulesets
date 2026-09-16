rule TTP_XOR_MULT_DOSStub_87e3 {
  strings:
    $key_87e3 = { d3 8b [2] a7 93 [2] e0 91 [2] a7 80 [2] e9 8c [2] e5 86 [2] f2 8d [2] e9 c3 [2] d4 }

  condition:
    any of them
}