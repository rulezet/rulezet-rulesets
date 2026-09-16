rule TTP_XOR_MULT_DOSStub_f657 {
  strings:
    $key_f657 = { a2 3f [2] d6 27 [2] 91 25 [2] d6 34 [2] 98 38 [2] 94 32 [2] 83 39 [2] 98 77 [2] a5 }

  condition:
    any of them
}