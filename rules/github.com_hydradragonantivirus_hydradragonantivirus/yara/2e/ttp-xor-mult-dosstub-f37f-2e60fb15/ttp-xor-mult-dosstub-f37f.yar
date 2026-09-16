rule TTP_XOR_MULT_DOSStub_f37f {
  strings:
    $key_f37f = { a7 17 [2] d3 0f [2] 94 0d [2] d3 1c [2] 9d 10 [2] 91 1a [2] 86 11 [2] 9d 5f [2] a0 }

  condition:
    any of them
}