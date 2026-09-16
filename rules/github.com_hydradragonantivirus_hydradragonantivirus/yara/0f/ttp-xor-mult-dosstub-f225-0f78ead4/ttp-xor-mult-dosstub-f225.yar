rule TTP_XOR_MULT_DOSStub_f225 {
  strings:
    $key_f225 = { a6 4d [2] d2 55 [2] 95 57 [2] d2 46 [2] 9c 4a [2] 90 40 [2] 87 4b [2] 9c 05 [2] a1 }

  condition:
    any of them
}