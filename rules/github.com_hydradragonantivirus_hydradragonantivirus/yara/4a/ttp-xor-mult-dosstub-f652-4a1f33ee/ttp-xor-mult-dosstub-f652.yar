rule TTP_XOR_MULT_DOSStub_f652 {
  strings:
    $key_f652 = { a2 3a [2] d6 22 [2] 91 20 [2] d6 31 [2] 98 3d [2] 94 37 [2] 83 3c [2] 98 72 [2] a5 }

  condition:
    any of them
}