rule TTP_XOR_MULT_DOSStub_941b {
  strings:
    $key_941b = { c0 73 [2] b4 6b [2] f3 69 [2] b4 78 [2] fa 74 [2] f6 7e [2] e1 75 [2] fa 3b [2] c7 }

  condition:
    any of them
}