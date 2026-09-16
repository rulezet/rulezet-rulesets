rule TTP_XOR_MULT_DOSStub_816b {
  strings:
    $key_816b = { d5 03 [2] a1 1b [2] e6 19 [2] a1 08 [2] ef 04 [2] e3 0e [2] f4 05 [2] ef 4b [2] d2 }

  condition:
    any of them
}