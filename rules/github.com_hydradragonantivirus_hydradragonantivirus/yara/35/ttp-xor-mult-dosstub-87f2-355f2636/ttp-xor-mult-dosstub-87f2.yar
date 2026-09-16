rule TTP_XOR_MULT_DOSStub_87f2 {
  strings:
    $key_87f2 = { d3 9a [2] a7 82 [2] e0 80 [2] a7 91 [2] e9 9d [2] e5 97 [2] f2 9c [2] e9 d2 [2] d4 }

  condition:
    any of them
}