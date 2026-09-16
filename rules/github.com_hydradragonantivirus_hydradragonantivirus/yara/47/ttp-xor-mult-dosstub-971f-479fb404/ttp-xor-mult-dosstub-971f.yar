rule TTP_XOR_MULT_DOSStub_971f {
  strings:
    $key_971f = { c3 77 [2] b7 6f [2] f0 6d [2] b7 7c [2] f9 70 [2] f5 7a [2] e2 71 [2] f9 3f [2] c4 }

  condition:
    any of them
}