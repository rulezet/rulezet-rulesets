rule TTP_XOR_MULT_DOSStub_f26a {
  strings:
    $key_f26a = { a6 02 [2] d2 1a [2] 95 18 [2] d2 09 [2] 9c 05 [2] 90 0f [2] 87 04 [2] 9c 4a [2] a1 }

  condition:
    any of them
}