rule TTP_XOR_MULT_DOSStub_f352 {
  strings:
    $key_f352 = { a7 3a [2] d3 22 [2] 94 20 [2] d3 31 [2] 9d 3d [2] 91 37 [2] 86 3c [2] 9d 72 [2] a0 }

  condition:
    any of them
}