rule TTP_XOR_MULT_DOSStub_12f9 {
  strings:
    $key_12f9 = { 46 91 [2] 32 89 [2] 75 8b [2] 32 9a [2] 7c 96 [2] 70 9c [2] 67 97 [2] 7c d9 [2] 41 }

  condition:
    any of them
}