rule TTP_XOR_MULT_DOSStub_3ce4 {
  strings:
    $key_3ce4 = { 68 8c [2] 1c 94 [2] 5b 96 [2] 1c 87 [2] 52 8b [2] 5e 81 [2] 49 8a [2] 52 c4 [2] 6f }

  condition:
    any of them
}