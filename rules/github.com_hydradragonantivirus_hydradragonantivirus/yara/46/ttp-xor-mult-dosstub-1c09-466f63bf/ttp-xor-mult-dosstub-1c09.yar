rule TTP_XOR_MULT_DOSStub_1c09 {
  strings:
    $key_1c09 = { 48 61 [2] 3c 79 [2] 7b 7b [2] 3c 6a [2] 72 66 [2] 7e 6c [2] 69 67 [2] 72 29 [2] 4f }

  condition:
    any of them
}