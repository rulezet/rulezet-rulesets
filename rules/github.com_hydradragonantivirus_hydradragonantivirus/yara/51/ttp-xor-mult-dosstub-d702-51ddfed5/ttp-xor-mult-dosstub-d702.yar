rule TTP_XOR_MULT_DOSStub_d702 {
  strings:
    $key_d702 = { 83 6a [2] f7 72 [2] b0 70 [2] f7 61 [2] b9 6d [2] b5 67 [2] a2 6c [2] b9 22 [2] 84 }

  condition:
    any of them
}