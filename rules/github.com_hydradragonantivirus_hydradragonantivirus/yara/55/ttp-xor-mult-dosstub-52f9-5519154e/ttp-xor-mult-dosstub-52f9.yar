rule TTP_XOR_MULT_DOSStub_52f9 {
  strings:
    $key_52f9 = { 06 91 [2] 72 89 [2] 35 8b [2] 72 9a [2] 3c 96 [2] 30 9c [2] 27 97 [2] 3c d9 [2] 01 }

  condition:
    any of them
}