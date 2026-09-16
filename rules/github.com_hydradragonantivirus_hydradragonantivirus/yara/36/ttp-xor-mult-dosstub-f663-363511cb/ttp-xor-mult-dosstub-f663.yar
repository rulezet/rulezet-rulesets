rule TTP_XOR_MULT_DOSStub_f663 {
  strings:
    $key_f663 = { a2 0b [2] d6 13 [2] 91 11 [2] d6 00 [2] 98 0c [2] 94 06 [2] 83 0d [2] 98 43 [2] a5 }

  condition:
    any of them
}