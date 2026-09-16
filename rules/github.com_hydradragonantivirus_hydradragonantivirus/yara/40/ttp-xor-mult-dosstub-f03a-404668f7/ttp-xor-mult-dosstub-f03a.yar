rule TTP_XOR_MULT_DOSStub_f03a {
  strings:
    $key_f03a = { a4 52 [2] d0 4a [2] 97 48 [2] d0 59 [2] 9e 55 [2] 92 5f [2] 85 54 [2] 9e 1a [2] a3 }

  condition:
    any of them
}