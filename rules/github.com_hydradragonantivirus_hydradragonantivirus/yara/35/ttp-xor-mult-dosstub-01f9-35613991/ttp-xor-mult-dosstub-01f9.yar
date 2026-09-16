rule TTP_XOR_MULT_DOSStub_01f9 {
  strings:
    $key_01f9 = { 55 91 [2] 21 89 [2] 66 8b [2] 21 9a [2] 6f 96 [2] 63 9c [2] 74 97 [2] 6f d9 [2] 52 }

  condition:
    any of them
}