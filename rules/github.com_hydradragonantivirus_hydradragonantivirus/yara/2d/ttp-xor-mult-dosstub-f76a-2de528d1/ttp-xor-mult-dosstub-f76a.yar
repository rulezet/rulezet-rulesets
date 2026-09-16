rule TTP_XOR_MULT_DOSStub_f76a {
  strings:
    $key_f76a = { a3 02 [2] d7 1a [2] 90 18 [2] d7 09 [2] 99 05 [2] 95 0f [2] 82 04 [2] 99 4a [2] a4 }

  condition:
    any of them
}