rule TTP_XOR_MULT_DOSStub_f374 {
  strings:
    $key_f374 = { a7 1c [2] d3 04 [2] 94 06 [2] d3 17 [2] 9d 1b [2] 91 11 [2] 86 1a [2] 9d 54 [2] a0 }

  condition:
    any of them
}