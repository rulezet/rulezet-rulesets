rule TTP_XOR_MULT_DOSStub_f363 {
  strings:
    $key_f363 = { a7 0b [2] d3 13 [2] 94 11 [2] d3 00 [2] 9d 0c [2] 91 06 [2] 86 0d [2] 9d 43 [2] a0 }

  condition:
    any of them
}