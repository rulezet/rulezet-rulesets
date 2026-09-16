rule TTP_XOR_MULT_DOSStub_0a25 {
  strings:
    $key_0a25 = { 5e 4d [2] 2a 55 [2] 6d 57 [2] 2a 46 [2] 64 4a [2] 68 40 [2] 7f 4b [2] 64 05 [2] 59 }

  condition:
    any of them
}