rule TTP_XOR_MULT_DOSStub_8722 {
  strings:
    $key_8722 = { d3 4a [2] a7 52 [2] e0 50 [2] a7 41 [2] e9 4d [2] e5 47 [2] f2 4c [2] e9 02 [2] d4 }

  condition:
    any of them
}