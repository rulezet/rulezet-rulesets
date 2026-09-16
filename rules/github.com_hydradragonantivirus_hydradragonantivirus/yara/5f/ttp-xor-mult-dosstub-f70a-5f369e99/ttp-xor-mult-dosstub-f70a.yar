rule TTP_XOR_MULT_DOSStub_f70a {
  strings:
    $key_f70a = { a3 62 [2] d7 7a [2] 90 78 [2] d7 69 [2] 99 65 [2] 95 6f [2] 82 64 [2] 99 2a [2] a4 }

  condition:
    any of them
}