rule TTP_XOR_MULT_DOSStub_d725 {
  strings:
    $key_d725 = { 83 4d [2] f7 55 [2] b0 57 [2] f7 46 [2] b9 4a [2] b5 40 [2] a2 4b [2] b9 05 [2] 84 }

  condition:
    any of them
}