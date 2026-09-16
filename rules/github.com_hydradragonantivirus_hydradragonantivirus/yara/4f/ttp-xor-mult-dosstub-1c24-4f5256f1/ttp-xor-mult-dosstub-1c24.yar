rule TTP_XOR_MULT_DOSStub_1c24 {
  strings:
    $key_1c24 = { 48 4c [2] 3c 54 [2] 7b 56 [2] 3c 47 [2] 72 4b [2] 7e 41 [2] 69 4a [2] 72 04 [2] 4f }

  condition:
    any of them
}