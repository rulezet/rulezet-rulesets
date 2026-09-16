rule TTP_XOR_MULT_DOSStub_0a38 {
  strings:
    $key_0a38 = { 5e 50 [2] 2a 48 [2] 6d 4a [2] 2a 5b [2] 64 57 [2] 68 5d [2] 7f 56 [2] 64 18 [2] 59 }

  condition:
    any of them
}