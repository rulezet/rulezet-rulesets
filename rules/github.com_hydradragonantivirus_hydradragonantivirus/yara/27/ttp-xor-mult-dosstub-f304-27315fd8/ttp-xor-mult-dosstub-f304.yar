rule TTP_XOR_MULT_DOSStub_f304 {
  strings:
    $key_f304 = { a7 6c [2] d3 74 [2] 94 76 [2] d3 67 [2] 9d 6b [2] 91 61 [2] 86 6a [2] 9d 24 [2] a0 }

  condition:
    any of them
}