rule TTP_XOR_MULT_DOSStub_90f2 {
  strings:
    $key_90f2 = { c4 9a [2] b0 82 [2] f7 80 [2] b0 91 [2] fe 9d [2] f2 97 [2] e5 9c [2] fe d2 [2] c3 }

  condition:
    any of them
}