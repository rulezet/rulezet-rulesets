rule TTP_XOR_MULT_DOSStub_8323 {
  strings:
    $key_8323 = { d7 4b [2] a3 53 [2] e4 51 [2] a3 40 [2] ed 4c [2] e1 46 [2] f6 4d [2] ed 03 [2] d0 }

  condition:
    any of them
}