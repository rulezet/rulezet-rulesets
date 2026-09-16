rule TTP_XOR_MULT_DOSStub_19e4 {
  strings:
    $key_19e4 = { 4d 8c [2] 39 94 [2] 7e 96 [2] 39 87 [2] 77 8b [2] 7b 81 [2] 6c 8a [2] 77 c4 [2] 4a }

  condition:
    any of them
}