rule TTP_XOR_MULT_DOSStub_f379 {
  strings:
    $key_f379 = { a7 11 [2] d3 09 [2] 94 0b [2] d3 1a [2] 9d 16 [2] 91 1c [2] 86 17 [2] 9d 59 [2] a0 }

  condition:
    any of them
}