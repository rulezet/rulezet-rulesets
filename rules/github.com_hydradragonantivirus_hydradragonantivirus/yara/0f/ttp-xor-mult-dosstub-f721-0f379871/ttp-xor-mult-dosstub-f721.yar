rule TTP_XOR_MULT_DOSStub_f721 {
  strings:
    $key_f721 = { a3 49 [2] d7 51 [2] 90 53 [2] d7 42 [2] 99 4e [2] 95 44 [2] 82 4f [2] 99 01 [2] a4 }

  condition:
    any of them
}