rule TTP_XOR_MULT_DOSStub_0a15 {
  strings:
    $key_0a15 = { 5e 7d [2] 2a 65 [2] 6d 67 [2] 2a 76 [2] 64 7a [2] 68 70 [2] 7f 7b [2] 64 35 [2] 59 }

  condition:
    any of them
}