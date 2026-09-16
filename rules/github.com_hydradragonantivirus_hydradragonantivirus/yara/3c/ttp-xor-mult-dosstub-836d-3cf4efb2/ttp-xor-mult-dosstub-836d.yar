rule TTP_XOR_MULT_DOSStub_836d {
  strings:
    $key_836d = { d7 05 [2] a3 1d [2] e4 1f [2] a3 0e [2] ed 02 [2] e1 08 [2] f6 03 [2] ed 4d [2] d0 }

  condition:
    any of them
}