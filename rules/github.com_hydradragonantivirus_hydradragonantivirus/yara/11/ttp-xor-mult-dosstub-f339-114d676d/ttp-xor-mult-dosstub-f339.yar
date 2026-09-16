rule TTP_XOR_MULT_DOSStub_f339 {
  strings:
    $key_f339 = { a7 51 [2] d3 49 [2] 94 4b [2] d3 5a [2] 9d 56 [2] 91 5c [2] 86 57 [2] 9d 19 [2] a0 }

  condition:
    any of them
}