rule TTP_XOR_MULT_DOSStub_0be4 {
  strings:
    $key_0be4 = { 5f 8c [2] 2b 94 [2] 6c 96 [2] 2b 87 [2] 65 8b [2] 69 81 [2] 7e 8a [2] 65 c4 [2] 58 }

  condition:
    any of them
}