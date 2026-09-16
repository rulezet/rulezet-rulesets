rule TTP_XOR_MULT_DOSStub_31f9 {
  strings:
    $key_31f9 = { 65 91 [2] 11 89 [2] 56 8b [2] 11 9a [2] 5f 96 [2] 53 9c [2] 44 97 [2] 5f d9 [2] 62 }

  condition:
    any of them
}