rule TTP_XOR_MULT_DOSStub_0ae5 {
  strings:
    $key_0ae5 = { 5e 8d [2] 2a 95 [2] 6d 97 [2] 2a 86 [2] 64 8a [2] 68 80 [2] 7f 8b [2] 64 c5 [2] 59 }

  condition:
    any of them
}