rule TTP_XOR_MULT_DOSStub_f204 {
  strings:
    $key_f204 = { a6 6c [2] d2 74 [2] 95 76 [2] d2 67 [2] 9c 6b [2] 90 61 [2] 87 6a [2] 9c 24 [2] a1 }

  condition:
    any of them
}