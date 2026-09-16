rule TTP_XOR_MULT_DOSStub_1ce8 {
  strings:
    $key_1ce8 = { 48 80 [2] 3c 98 [2] 7b 9a [2] 3c 8b [2] 72 87 [2] 7e 8d [2] 69 86 [2] 72 c8 [2] 4f }

  condition:
    any of them
}