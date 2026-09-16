rule TTP_XOR_MULT_DOSStub_f677 {
  strings:
    $key_f677 = { a2 1f [2] d6 07 [2] 91 05 [2] d6 14 [2] 98 18 [2] 94 12 [2] 83 19 [2] 98 57 [2] a5 }

  condition:
    any of them
}