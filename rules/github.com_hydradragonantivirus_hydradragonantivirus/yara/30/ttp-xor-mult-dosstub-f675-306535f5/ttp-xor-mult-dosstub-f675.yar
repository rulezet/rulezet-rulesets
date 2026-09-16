rule TTP_XOR_MULT_DOSStub_f675 {
  strings:
    $key_f675 = { a2 1d [2] d6 05 [2] 91 07 [2] d6 16 [2] 98 1a [2] 94 10 [2] 83 1b [2] 98 55 [2] a5 }

  condition:
    any of them
}