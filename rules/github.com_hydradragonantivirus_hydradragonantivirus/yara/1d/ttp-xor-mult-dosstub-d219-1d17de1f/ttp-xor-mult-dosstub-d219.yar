rule TTP_XOR_MULT_DOSStub_d219 {
  strings:
    $key_d219 = { 86 71 [2] f2 69 [2] b5 6b [2] f2 7a [2] bc 76 [2] b0 7c [2] a7 77 [2] bc 39 [2] 81 }

  condition:
    any of them
}