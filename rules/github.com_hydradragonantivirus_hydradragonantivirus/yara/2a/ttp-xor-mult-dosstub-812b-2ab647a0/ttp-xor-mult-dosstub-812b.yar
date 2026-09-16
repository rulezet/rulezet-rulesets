rule TTP_XOR_MULT_DOSStub_812b {
  strings:
    $key_812b = { d5 43 [2] a1 5b [2] e6 59 [2] a1 48 [2] ef 44 [2] e3 4e [2] f4 45 [2] ef 0b [2] d2 }

  condition:
    any of them
}