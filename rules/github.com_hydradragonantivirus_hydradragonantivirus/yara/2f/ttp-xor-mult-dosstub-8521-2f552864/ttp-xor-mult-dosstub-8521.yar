rule TTP_XOR_MULT_DOSStub_8521 {
  strings:
    $key_8521 = { d1 49 [2] a5 51 [2] e2 53 [2] a5 42 [2] eb 4e [2] e7 44 [2] f0 4f [2] eb 01 [2] d6 }

  condition:
    any of them
}