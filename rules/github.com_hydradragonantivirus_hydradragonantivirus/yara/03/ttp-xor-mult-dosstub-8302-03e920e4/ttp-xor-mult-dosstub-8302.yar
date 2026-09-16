rule TTP_XOR_MULT_DOSStub_8302 {
  strings:
    $key_8302 = { d7 6a [2] a3 72 [2] e4 70 [2] a3 61 [2] ed 6d [2] e1 67 [2] f6 6c [2] ed 22 [2] d0 }

  condition:
    any of them
}