rule TTP_XOR_MULT_DOSStub_f46f {
  strings:
    $key_f46f = { a0 07 [2] d4 1f [2] 93 1d [2] d4 0c [2] 9a 00 [2] 96 0a [2] 81 01 [2] 9a 4f [2] a7 }

  condition:
    any of them
}