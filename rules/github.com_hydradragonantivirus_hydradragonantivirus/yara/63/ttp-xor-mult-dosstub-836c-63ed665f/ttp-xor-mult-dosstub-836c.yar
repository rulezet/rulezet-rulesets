rule TTP_XOR_MULT_DOSStub_836c {
  strings:
    $key_836c = { d7 04 [2] a3 1c [2] e4 1e [2] a3 0f [2] ed 03 [2] e1 09 [2] f6 02 [2] ed 4c [2] d0 }

  condition:
    any of them
}