rule TTP_XOR_MULT_DOSStub_f6f8 {
  strings:
    $key_f6f8 = { a2 90 [2] d6 88 [2] 91 8a [2] d6 9b [2] 98 97 [2] 94 9d [2] 83 96 [2] 98 d8 [2] a5 }

  condition:
    any of them
}