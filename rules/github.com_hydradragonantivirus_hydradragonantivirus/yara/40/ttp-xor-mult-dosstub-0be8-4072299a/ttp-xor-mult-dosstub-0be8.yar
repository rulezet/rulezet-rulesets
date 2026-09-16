rule TTP_XOR_MULT_DOSStub_0be8 {
  strings:
    $key_0be8 = { 5f 80 [2] 2b 98 [2] 6c 9a [2] 2b 8b [2] 65 87 [2] 69 8d [2] 7e 86 [2] 65 c8 [2] 58 }

  condition:
    any of them
}