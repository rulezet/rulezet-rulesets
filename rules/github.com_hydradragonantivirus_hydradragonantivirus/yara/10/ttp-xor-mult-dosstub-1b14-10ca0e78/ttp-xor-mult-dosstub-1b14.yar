rule TTP_XOR_MULT_DOSStub_1b14 {
  strings:
    $key_1b14 = { 4f 7c [2] 3b 64 [2] 7c 66 [2] 3b 77 [2] 75 7b [2] 79 71 [2] 6e 7a [2] 75 34 [2] 48 }

  condition:
    any of them
}