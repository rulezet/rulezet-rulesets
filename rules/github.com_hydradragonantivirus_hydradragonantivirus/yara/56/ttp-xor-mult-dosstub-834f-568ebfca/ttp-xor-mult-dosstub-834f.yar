rule TTP_XOR_MULT_DOSStub_834f {
  strings:
    $key_834f = { d7 27 [2] a3 3f [2] e4 3d [2] a3 2c [2] ed 20 [2] e1 2a [2] f6 21 [2] ed 6f [2] d0 }

  condition:
    any of them
}