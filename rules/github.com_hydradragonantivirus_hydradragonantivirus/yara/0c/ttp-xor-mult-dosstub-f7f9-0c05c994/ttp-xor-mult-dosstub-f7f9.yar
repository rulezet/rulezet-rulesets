rule TTP_XOR_MULT_DOSStub_f7f9 {
  strings:
    $key_f7f9 = { a3 91 [2] d7 89 [2] 90 8b [2] d7 9a [2] 99 96 [2] 95 9c [2] 82 97 [2] 99 d9 [2] a4 }

  condition:
    any of them
}