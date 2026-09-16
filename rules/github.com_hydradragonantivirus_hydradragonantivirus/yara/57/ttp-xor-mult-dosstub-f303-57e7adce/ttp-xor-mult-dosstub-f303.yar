rule TTP_XOR_MULT_DOSStub_f303 {
  strings:
    $key_f303 = { a7 6b [2] d3 73 [2] 94 71 [2] d3 60 [2] 9d 6c [2] 91 66 [2] 86 6d [2] 9d 23 [2] a0 }

  condition:
    any of them
}