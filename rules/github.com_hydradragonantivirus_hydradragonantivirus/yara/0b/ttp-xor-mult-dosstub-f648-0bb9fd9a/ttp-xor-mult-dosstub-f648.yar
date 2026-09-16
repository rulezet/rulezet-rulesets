rule TTP_XOR_MULT_DOSStub_f648 {
  strings:
    $key_f648 = { a2 20 [2] d6 38 [2] 91 3a [2] d6 2b [2] 98 27 [2] 94 2d [2] 83 26 [2] 98 68 [2] a5 }

  condition:
    any of them
}