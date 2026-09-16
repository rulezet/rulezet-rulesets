rule TTP_XOR_MULT_DOSStub_f7e5 {
  strings:
    $key_f7e5 = { a3 8d [2] d7 95 [2] 90 97 [2] d7 86 [2] 99 8a [2] 95 80 [2] 82 8b [2] 99 c5 [2] a4 }

  condition:
    any of them
}