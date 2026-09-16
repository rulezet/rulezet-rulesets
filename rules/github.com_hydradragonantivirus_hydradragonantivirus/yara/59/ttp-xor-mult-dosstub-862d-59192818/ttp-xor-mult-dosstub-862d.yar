rule TTP_XOR_MULT_DOSStub_862d {
  strings:
    $key_862d = { d2 45 [2] a6 5d [2] e1 5f [2] a6 4e [2] e8 42 [2] e4 48 [2] f3 43 [2] e8 0d [2] d5 }

  condition:
    any of them
}