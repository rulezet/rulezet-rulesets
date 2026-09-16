rule TTP_XOR_MULT_DOSStub_831f {
  strings:
    $key_831f = { d7 77 [2] a3 6f [2] e4 6d [2] a3 7c [2] ed 70 [2] e1 7a [2] f6 71 [2] ed 3f [2] d0 }

  condition:
    any of them
}