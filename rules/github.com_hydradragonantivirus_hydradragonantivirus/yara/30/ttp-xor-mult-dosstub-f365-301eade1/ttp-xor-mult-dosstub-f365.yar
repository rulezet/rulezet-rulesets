rule TTP_XOR_MULT_DOSStub_f365 {
  strings:
    $key_f365 = { a7 0d [2] d3 15 [2] 94 17 [2] d3 06 [2] 9d 0a [2] 91 00 [2] 86 0b [2] 9d 45 [2] a0 }

  condition:
    any of them
}