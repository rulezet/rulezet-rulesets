rule TTP_XOR_MULT_DOSStub_d20e {
  strings:
    $key_d20e = { 86 66 [2] f2 7e [2] b5 7c [2] f2 6d [2] bc 61 [2] b0 6b [2] a7 60 [2] bc 2e [2] 81 }

  condition:
    any of them
}