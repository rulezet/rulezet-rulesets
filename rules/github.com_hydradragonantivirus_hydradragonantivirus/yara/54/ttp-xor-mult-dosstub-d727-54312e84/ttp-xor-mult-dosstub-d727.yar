rule TTP_XOR_MULT_DOSStub_d727 {
  strings:
    $key_d727 = { 83 4f [2] f7 57 [2] b0 55 [2] f7 44 [2] b9 48 [2] b5 42 [2] a2 49 [2] b9 07 [2] 84 }

  condition:
    any of them
}