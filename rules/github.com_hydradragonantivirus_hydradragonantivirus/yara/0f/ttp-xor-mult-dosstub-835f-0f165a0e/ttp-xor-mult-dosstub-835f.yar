rule TTP_XOR_MULT_DOSStub_835f {
  strings:
    $key_835f = { d7 37 [2] a3 2f [2] e4 2d [2] a3 3c [2] ed 30 [2] e1 3a [2] f6 31 [2] ed 7f [2] d0 }

  condition:
    any of them
}