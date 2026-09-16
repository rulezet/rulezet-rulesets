rule TTP_XOR_MULT_DOSStub_907f {
  strings:
    $key_907f = { c4 17 [2] b0 0f [2] f7 0d [2] b0 1c [2] fe 10 [2] f2 1a [2] e5 11 [2] fe 5f [2] c3 }

  condition:
    any of them
}