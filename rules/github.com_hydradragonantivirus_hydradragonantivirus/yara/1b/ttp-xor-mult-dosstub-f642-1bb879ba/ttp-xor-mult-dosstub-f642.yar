rule TTP_XOR_MULT_DOSStub_f642 {
  strings:
    $key_f642 = { a2 2a [2] d6 32 [2] 91 30 [2] d6 21 [2] 98 2d [2] 94 27 [2] 83 2c [2] 98 62 [2] a5 }

  condition:
    any of them
}