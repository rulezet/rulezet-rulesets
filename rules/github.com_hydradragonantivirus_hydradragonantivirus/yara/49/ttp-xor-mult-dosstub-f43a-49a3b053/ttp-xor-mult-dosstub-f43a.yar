rule TTP_XOR_MULT_DOSStub_f43a {
  strings:
    $key_f43a = { a0 52 [2] d4 4a [2] 93 48 [2] d4 59 [2] 9a 55 [2] 96 5f [2] 81 54 [2] 9a 1a [2] a7 }

  condition:
    any of them
}