rule TTP_XOR_MULT_DOSStub_f02a {
  strings:
    $key_f02a = { a4 42 [2] d0 5a [2] 97 58 [2] d0 49 [2] 9e 45 [2] 92 4f [2] 85 44 [2] 9e 0a [2] a3 }

  condition:
    any of them
}