rule TTP_XOR_MULT_DOSStub_f66d {
  strings:
    $key_f66d = { a2 05 [2] d6 1d [2] 91 1f [2] d6 0e [2] 98 02 [2] 94 08 [2] 83 03 [2] 98 4d [2] a5 }

  condition:
    any of them
}