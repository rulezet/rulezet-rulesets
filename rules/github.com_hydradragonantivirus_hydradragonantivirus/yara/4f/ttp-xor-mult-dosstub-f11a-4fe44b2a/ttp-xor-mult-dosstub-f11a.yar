rule TTP_XOR_MULT_DOSStub_f11a {
  strings:
    $key_f11a = { a5 72 [2] d1 6a [2] 96 68 [2] d1 79 [2] 9f 75 [2] 93 7f [2] 84 74 [2] 9f 3a [2] a2 }

  condition:
    any of them
}