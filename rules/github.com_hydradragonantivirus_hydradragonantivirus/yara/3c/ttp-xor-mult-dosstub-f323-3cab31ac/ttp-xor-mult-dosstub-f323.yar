rule TTP_XOR_MULT_DOSStub_f323 {
  strings:
    $key_f323 = { a7 4b [2] d3 53 [2] 94 51 [2] d3 40 [2] 9d 4c [2] 91 46 [2] 86 4d [2] 9d 03 [2] a0 }

  condition:
    any of them
}