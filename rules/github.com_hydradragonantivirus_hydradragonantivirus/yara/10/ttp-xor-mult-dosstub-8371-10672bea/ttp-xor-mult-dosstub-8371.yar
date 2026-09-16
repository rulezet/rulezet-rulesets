rule TTP_XOR_MULT_DOSStub_8371 {
  strings:
    $key_8371 = { d7 19 [2] a3 01 [2] e4 03 [2] a3 12 [2] ed 1e [2] e1 14 [2] f6 1f [2] ed 51 [2] d0 }

  condition:
    any of them
}