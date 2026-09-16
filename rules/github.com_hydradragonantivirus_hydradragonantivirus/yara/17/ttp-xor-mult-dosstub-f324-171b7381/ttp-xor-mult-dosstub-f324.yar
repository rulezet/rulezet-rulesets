rule TTP_XOR_MULT_DOSStub_f324 {
  strings:
    $key_f324 = { a7 4c [2] d3 54 [2] 94 56 [2] d3 47 [2] 9d 4b [2] 91 41 [2] 86 4a [2] 9d 04 [2] a0 }

  condition:
    any of them
}