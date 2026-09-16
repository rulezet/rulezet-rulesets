rule TTP_XOR_MULT_DOSStub_f424 {
  strings:
    $key_f424 = { a0 4c [2] d4 54 [2] 93 56 [2] d4 47 [2] 9a 4b [2] 96 41 [2] 81 4a [2] 9a 04 [2] a7 }

  condition:
    any of them
}