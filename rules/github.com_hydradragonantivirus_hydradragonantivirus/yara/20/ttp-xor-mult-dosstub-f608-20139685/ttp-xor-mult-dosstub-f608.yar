rule TTP_XOR_MULT_DOSStub_f608 {
  strings:
    $key_f608 = { a2 60 [2] d6 78 [2] 91 7a [2] d6 6b [2] 98 67 [2] 94 6d [2] 83 66 [2] 98 28 [2] a5 }

  condition:
    any of them
}