rule TTP_XOR_MULT_DOSStub_0af5 {
  strings:
    $key_0af5 = { 5e 9d [2] 2a 85 [2] 6d 87 [2] 2a 96 [2] 64 9a [2] 68 90 [2] 7f 9b [2] 64 d5 [2] 59 }

  condition:
    any of them
}