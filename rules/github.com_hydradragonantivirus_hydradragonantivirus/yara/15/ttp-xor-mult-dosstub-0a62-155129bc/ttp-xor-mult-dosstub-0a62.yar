rule TTP_XOR_MULT_DOSStub_0a62 {
  strings:
    $key_0a62 = { 5e 0a [2] 2a 12 [2] 6d 10 [2] 2a 01 [2] 64 0d [2] 68 07 [2] 7f 0c [2] 64 42 [2] 59 }

  condition:
    any of them
}