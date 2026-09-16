rule TTP_XOR_MULT_DOSStub_f313 {
  strings:
    $key_f313 = { a7 7b [2] d3 63 [2] 94 61 [2] d3 70 [2] 9d 7c [2] 91 76 [2] 86 7d [2] 9d 33 [2] a0 }

  condition:
    any of them
}