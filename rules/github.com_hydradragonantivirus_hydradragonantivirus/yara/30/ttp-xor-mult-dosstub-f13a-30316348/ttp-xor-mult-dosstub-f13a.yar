rule TTP_XOR_MULT_DOSStub_f13a {
  strings:
    $key_f13a = { a5 52 [2] d1 4a [2] 96 48 [2] d1 59 [2] 9f 55 [2] 93 5f [2] 84 54 [2] 9f 1a [2] a2 }

  condition:
    any of them
}