rule TTP_XOR_MULT_DOSStub_11f9 {
  strings:
    $key_11f9 = { 45 91 [2] 31 89 [2] 76 8b [2] 31 9a [2] 7f 96 [2] 73 9c [2] 64 97 [2] 7f d9 [2] 42 }

  condition:
    any of them
}