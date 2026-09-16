rule TTP_XOR_MULT_DOSStub_0918 {
  strings:
    $key_0918 = { 5d 70 [2] 29 68 [2] 6e 6a [2] 29 7b [2] 67 77 [2] 6b 7d [2] 7c 76 [2] 67 38 [2] 5a }

  condition:
    any of them
}