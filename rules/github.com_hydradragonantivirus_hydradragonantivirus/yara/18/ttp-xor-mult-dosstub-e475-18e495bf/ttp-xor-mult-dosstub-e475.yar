rule TTP_XOR_MULT_DOSStub_e475 {
  strings:
    $key_e475 = { b0 1d [2] c4 05 [2] 83 07 [2] c4 16 [2] 8a 1a [2] 86 10 [2] 91 1b [2] 8a 55 [2] b7 }

  condition:
    any of them
}