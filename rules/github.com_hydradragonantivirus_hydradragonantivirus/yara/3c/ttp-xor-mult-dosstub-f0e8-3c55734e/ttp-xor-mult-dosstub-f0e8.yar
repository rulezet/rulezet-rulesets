rule TTP_XOR_MULT_DOSStub_f0e8 {
  strings:
    $key_f0e8 = { a4 80 [2] d0 98 [2] 97 9a [2] d0 8b [2] 9e 87 [2] 92 8d [2] 85 86 [2] 9e c8 [2] a3 }

  condition:
    any of them
}