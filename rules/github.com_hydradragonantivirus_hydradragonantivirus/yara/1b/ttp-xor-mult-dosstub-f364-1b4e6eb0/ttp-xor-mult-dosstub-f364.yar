rule TTP_XOR_MULT_DOSStub_f364 {
  strings:
    $key_f364 = { a7 0c [2] d3 14 [2] 94 16 [2] d3 07 [2] 9d 0b [2] 91 01 [2] 86 0a [2] 9d 44 [2] a0 }

  condition:
    any of them
}