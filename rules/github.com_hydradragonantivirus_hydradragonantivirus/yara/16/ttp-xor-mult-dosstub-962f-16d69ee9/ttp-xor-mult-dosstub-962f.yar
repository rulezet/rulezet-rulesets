rule TTP_XOR_MULT_DOSStub_962f {
  strings:
    $key_962f = { c2 47 [2] b6 5f [2] f1 5d [2] b6 4c [2] f8 40 [2] f4 4a [2] e3 41 [2] f8 0f [2] c5 }

  condition:
    any of them
}