rule TTP_XOR_MULT_DOSStub_f6f4 {
  strings:
    $key_f6f4 = { a2 9c [2] d6 84 [2] 91 86 [2] d6 97 [2] 98 9b [2] 94 91 [2] 83 9a [2] 98 d4 [2] a5 }

  condition:
    any of them
}