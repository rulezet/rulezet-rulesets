rule TTP_XOR_MULT_DOSStub_902f {
  strings:
    $key_902f = { c4 47 [2] b0 5f [2] f7 5d [2] b0 4c [2] fe 40 [2] f2 4a [2] e5 41 [2] fe 0f [2] c3 }

  condition:
    any of them
}