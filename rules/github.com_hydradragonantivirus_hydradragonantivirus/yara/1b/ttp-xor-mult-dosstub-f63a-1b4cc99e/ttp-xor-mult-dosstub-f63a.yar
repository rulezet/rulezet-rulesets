rule TTP_XOR_MULT_DOSStub_f63a {
  strings:
    $key_f63a = { a2 52 [2] d6 4a [2] 91 48 [2] d6 59 [2] 98 55 [2] 94 5f [2] 83 54 [2] 98 1a [2] a5 }

  condition:
    any of them
}