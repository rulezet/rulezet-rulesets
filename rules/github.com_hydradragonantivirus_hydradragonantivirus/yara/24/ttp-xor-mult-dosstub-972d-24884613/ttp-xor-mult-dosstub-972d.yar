rule TTP_XOR_MULT_DOSStub_972d {
  strings:
    $key_972d = { c3 45 [2] b7 5d [2] f0 5f [2] b7 4e [2] f9 42 [2] f5 48 [2] e2 43 [2] f9 0d [2] c4 }

  condition:
    any of them
}