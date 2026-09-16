rule TTP_XOR_MULT_DOSStub_f335 {
  strings:
    $key_f335 = { a7 5d [2] d3 45 [2] 94 47 [2] d3 56 [2] 9d 5a [2] 91 50 [2] 86 5b [2] 9d 15 [2] a0 }

  condition:
    any of them
}