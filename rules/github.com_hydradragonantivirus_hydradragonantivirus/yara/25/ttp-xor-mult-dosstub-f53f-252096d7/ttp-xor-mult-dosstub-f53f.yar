rule TTP_XOR_MULT_DOSStub_f53f {
  strings:
    $key_f53f = { a1 57 [2] d5 4f [2] 92 4d [2] d5 5c [2] 9b 50 [2] 97 5a [2] 80 51 [2] 9b 1f [2] a6 }

  condition:
    any of them
}