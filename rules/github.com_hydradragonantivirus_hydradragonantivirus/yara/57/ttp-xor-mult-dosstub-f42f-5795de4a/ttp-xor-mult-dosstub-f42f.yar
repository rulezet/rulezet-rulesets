rule TTP_XOR_MULT_DOSStub_f42f {
  strings:
    $key_f42f = { a0 47 [2] d4 5f [2] 93 5d [2] d4 4c [2] 9a 40 [2] 96 4a [2] 81 41 [2] 9a 0f [2] a7 }

  condition:
    any of them
}