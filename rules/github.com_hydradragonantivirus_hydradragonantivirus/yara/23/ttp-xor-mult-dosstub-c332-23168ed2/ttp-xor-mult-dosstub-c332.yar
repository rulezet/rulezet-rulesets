rule TTP_XOR_MULT_DOSStub_c332 {
  strings:
    $key_c332 = { 97 5a [2] e3 42 [2] a4 40 [2] e3 51 [2] ad 5d [2] a1 57 [2] b6 5c [2] ad 12 [2] 90 }

  condition:
    any of them
}