rule TTP_XOR_MULT_DOSStub_4b14 {
  strings:
    $key_4b14 = { 1f 7c [2] 6b 64 [2] 2c 66 [2] 6b 77 [2] 25 7b [2] 29 71 [2] 3e 7a [2] 25 34 [2] 18 }

  condition:
    any of them
}