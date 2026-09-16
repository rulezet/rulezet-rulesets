rule TTP_XOR_MULT_DOSStub_0b14 {
  strings:
    $key_0b14 = { 5f 7c [2] 2b 64 [2] 6c 66 [2] 2b 77 [2] 65 7b [2] 69 71 [2] 7e 7a [2] 65 34 [2] 58 }

  condition:
    any of them
}