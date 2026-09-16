rule TTP_XOR_MULT_DOSStub_f0ef {
  strings:
    $key_f0ef = { a4 87 [2] d0 9f [2] 97 9d [2] d0 8c [2] 9e 80 [2] 92 8a [2] 85 81 [2] 9e cf [2] a3 }

  condition:
    any of them
}