rule TTP_XOR_MULT_DOSStub_f619 {
  strings:
    $key_f619 = { a2 71 [2] d6 69 [2] 91 6b [2] d6 7a [2] 98 76 [2] 94 7c [2] 83 77 [2] 98 39 [2] a5 }

  condition:
    any of them
}