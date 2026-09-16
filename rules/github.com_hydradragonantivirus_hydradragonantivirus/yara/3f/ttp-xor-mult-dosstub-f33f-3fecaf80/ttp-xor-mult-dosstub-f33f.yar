rule TTP_XOR_MULT_DOSStub_f33f {
  strings:
    $key_f33f = { a7 57 [2] d3 4f [2] 94 4d [2] d3 5c [2] 9d 50 [2] 91 5a [2] 86 51 [2] 9d 1f [2] a0 }

  condition:
    any of them
}