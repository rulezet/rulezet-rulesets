rule TTP_XOR_MULT_DOSStub_937c {
  strings:
    $key_937c = { c7 14 [2] b3 0c [2] f4 0e [2] b3 1f [2] fd 13 [2] f1 19 [2] e6 12 [2] fd 5c [2] c0 }

  condition:
    any of them
}