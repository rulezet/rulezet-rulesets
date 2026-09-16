rule TTP_XOR_MULT_DOSStub_16f9 {
  strings:
    $key_16f9 = { 42 91 [2] 36 89 [2] 71 8b [2] 36 9a [2] 78 96 [2] 74 9c [2] 63 97 [2] 78 d9 [2] 45 }

  condition:
    any of them
}