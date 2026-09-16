rule TTP_XOR_MULT_DOSStub_1b08 {
  strings:
    $key_1b08 = { 4f 60 [2] 3b 78 [2] 7c 7a [2] 3b 6b [2] 75 67 [2] 79 6d [2] 6e 66 [2] 75 28 [2] 48 }

  condition:
    any of them
}