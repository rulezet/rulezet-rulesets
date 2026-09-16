rule TTP_XOR_MULT_DOSStub_f213 {
  strings:
    $key_f213 = { a6 7b [2] d2 63 [2] 95 61 [2] d2 70 [2] 9c 7c [2] 90 76 [2] 87 7d [2] 9c 33 [2] a1 }

  condition:
    any of them
}