rule TTP_XOR_MULT_DOSStub_942d {
  strings:
    $key_942d = { c0 45 [2] b4 5d [2] f3 5f [2] b4 4e [2] fa 42 [2] f6 48 [2] e1 43 [2] fa 0d [2] c7 }

  condition:
    any of them
}