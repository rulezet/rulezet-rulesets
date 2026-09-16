rule TTP_XOR_MULT_DOSStub_d741 {
  strings:
    $key_d741 = { 83 29 [2] f7 31 [2] b0 33 [2] f7 22 [2] b9 2e [2] b5 24 [2] a2 2f [2] b9 61 [2] 84 }

  condition:
    any of them
}