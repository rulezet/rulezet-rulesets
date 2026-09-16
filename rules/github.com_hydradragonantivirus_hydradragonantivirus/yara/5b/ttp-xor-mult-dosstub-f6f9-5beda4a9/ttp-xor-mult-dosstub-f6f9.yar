rule TTP_XOR_MULT_DOSStub_f6f9 {
  strings:
    $key_f6f9 = { a2 91 [2] d6 89 [2] 91 8b [2] d6 9a [2] 98 96 [2] 94 9c [2] 83 97 [2] 98 d9 [2] a5 }

  condition:
    any of them
}