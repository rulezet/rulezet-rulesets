rule TTP_XOR_MULT_DOSStub_866a {
  strings:
    $key_866a = { d2 02 [2] a6 1a [2] e1 18 [2] a6 09 [2] e8 05 [2] e4 0f [2] f3 04 [2] e8 4a [2] d5 }

  condition:
    any of them
}