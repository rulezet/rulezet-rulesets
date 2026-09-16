rule TTP_XOR_MULT_DOSStub_09e9 {
  strings:
    $key_09e9 = { 5d 81 [2] 29 99 [2] 6e 9b [2] 29 8a [2] 67 86 [2] 6b 8c [2] 7c 87 [2] 67 c9 [2] 5a }

  condition:
    any of them
}