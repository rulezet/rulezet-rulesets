rule TTP_XOR_MULT_DOSStub_f474 {
  strings:
    $key_f474 = { a0 1c [2] d4 04 [2] 93 06 [2] d4 17 [2] 9a 1b [2] 96 11 [2] 81 1a [2] 9a 54 [2] a7 }

  condition:
    any of them
}