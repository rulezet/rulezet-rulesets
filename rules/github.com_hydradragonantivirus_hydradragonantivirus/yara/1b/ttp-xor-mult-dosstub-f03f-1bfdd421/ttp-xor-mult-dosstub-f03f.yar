rule TTP_XOR_MULT_DOSStub_f03f {
  strings:
    $key_f03f = { a4 57 [2] d0 4f [2] 97 4d [2] d0 5c [2] 9e 50 [2] 92 5a [2] 85 51 [2] 9e 1f [2] a3 }

  condition:
    any of them
}