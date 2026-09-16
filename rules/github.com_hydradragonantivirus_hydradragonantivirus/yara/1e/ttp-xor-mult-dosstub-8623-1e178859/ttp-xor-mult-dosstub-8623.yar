rule TTP_XOR_MULT_DOSStub_8623 {
  strings:
    $key_8623 = { d2 4b [2] a6 53 [2] e1 51 [2] a6 40 [2] e8 4c [2] e4 46 [2] f3 4d [2] e8 03 [2] d5 }

  condition:
    any of them
}