rule TTP_XOR_MULT_DOSStub_8523 {
  strings:
    $key_8523 = { d1 4b [2] a5 53 [2] e2 51 [2] a5 40 [2] eb 4c [2] e7 46 [2] f0 4d [2] eb 03 [2] d6 }

  condition:
    any of them
}