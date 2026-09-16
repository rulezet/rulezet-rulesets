rule TTP_XOR_MULT_DOSStub_f615 {
  strings:
    $key_f615 = { a2 7d [2] d6 65 [2] 91 67 [2] d6 76 [2] 98 7a [2] 94 70 [2] 83 7b [2] 98 35 [2] a5 }

  condition:
    any of them
}