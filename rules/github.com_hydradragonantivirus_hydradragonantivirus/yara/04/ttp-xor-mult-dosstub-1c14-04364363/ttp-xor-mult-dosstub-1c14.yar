rule TTP_XOR_MULT_DOSStub_1c14 {
  strings:
    $key_1c14 = { 48 7c [2] 3c 64 [2] 7b 66 [2] 3c 77 [2] 72 7b [2] 7e 71 [2] 69 7a [2] 72 34 [2] 4f }

  condition:
    any of them
}