rule TTP_XOR_MULT_DOSStub_862c {
  strings:
    $key_862c = { d2 44 [2] a6 5c [2] e1 5e [2] a6 4f [2] e8 43 [2] e4 49 [2] f3 42 [2] e8 0c [2] d5 }

  condition:
    any of them
}