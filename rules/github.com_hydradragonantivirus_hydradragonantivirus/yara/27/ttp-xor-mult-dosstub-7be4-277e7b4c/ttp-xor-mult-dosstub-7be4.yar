rule TTP_XOR_MULT_DOSStub_7be4 {
  strings:
    $key_7be4 = { 2f 8c [2] 5b 94 [2] 1c 96 [2] 5b 87 [2] 15 8b [2] 19 81 [2] 0e 8a [2] 15 c4 [2] 28 }

  condition:
    any of them
}