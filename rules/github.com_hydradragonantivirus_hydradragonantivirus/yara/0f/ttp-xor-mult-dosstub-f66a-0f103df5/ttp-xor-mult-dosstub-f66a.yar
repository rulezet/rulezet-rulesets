rule TTP_XOR_MULT_DOSStub_f66a {
  strings:
    $key_f66a = { a2 02 [2] d6 1a [2] 91 18 [2] d6 09 [2] 98 05 [2] 94 0f [2] 83 04 [2] 98 4a [2] a5 }

  condition:
    any of them
}