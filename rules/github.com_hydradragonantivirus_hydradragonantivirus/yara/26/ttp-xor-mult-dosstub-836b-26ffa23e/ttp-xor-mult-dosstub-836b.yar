rule TTP_XOR_MULT_DOSStub_836b {
  strings:
    $key_836b = { d7 03 [2] a3 1b [2] e4 19 [2] a3 08 [2] ed 04 [2] e1 0e [2] f6 05 [2] ed 4b [2] d0 }

  condition:
    any of them
}