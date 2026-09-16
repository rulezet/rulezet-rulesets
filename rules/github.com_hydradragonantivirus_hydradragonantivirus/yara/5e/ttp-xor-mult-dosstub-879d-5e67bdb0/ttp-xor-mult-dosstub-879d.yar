rule TTP_XOR_MULT_DOSStub_879d {
  strings:
    $key_879d = { d3 f5 [2] a7 ed [2] e0 ef [2] a7 fe [2] e9 f2 [2] e5 f8 [2] f2 f3 [2] e9 bd [2] d4 }

  condition:
    any of them
}