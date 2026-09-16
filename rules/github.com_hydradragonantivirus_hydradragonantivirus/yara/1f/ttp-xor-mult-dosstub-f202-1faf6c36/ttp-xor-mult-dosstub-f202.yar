rule TTP_XOR_MULT_DOSStub_f202 {
  strings:
    $key_f202 = { a6 6a [2] d2 72 [2] 95 70 [2] d2 61 [2] 9c 6d [2] 90 67 [2] 87 6c [2] 9c 22 [2] a1 }

  condition:
    any of them
}