rule TTP_XOR_MULT_DOSStub_1b02 {
  strings:
    $key_1b02 = { 4f 6a [2] 3b 72 [2] 7c 70 [2] 3b 61 [2] 75 6d [2] 79 67 [2] 6e 6c [2] 75 22 [2] 48 }

  condition:
    any of them
}