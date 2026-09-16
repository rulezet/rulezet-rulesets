rule TTP_XOR_MULT_DOSStub_8735 {
  strings:
    $key_8735 = { d3 5d [2] a7 45 [2] e0 47 [2] a7 56 [2] e9 5a [2] e5 50 [2] f2 5b [2] e9 15 [2] d4 }

  condition:
    any of them
}