rule TTP_XOR_MULT_DOSStub_f57f {
  strings:
    $key_f57f = { a1 17 [2] d5 0f [2] 92 0d [2] d5 1c [2] 9b 10 [2] 97 1a [2] 80 11 [2] 9b 5f [2] a6 }

  condition:
    any of them
}