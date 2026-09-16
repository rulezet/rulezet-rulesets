rule TTP_XOR_MULT_DOSStub_d20f {
  strings:
    $key_d20f = { 86 67 [2] f2 7f [2] b5 7d [2] f2 6c [2] bc 60 [2] b0 6a [2] a7 61 [2] bc 2f [2] 81 }

  condition:
    any of them
}