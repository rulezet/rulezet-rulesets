rule TTP_XOR_MULT_DOSStub_0a35 {
  strings:
    $key_0a35 = { 5e 5d [2] 2a 45 [2] 6d 47 [2] 2a 56 [2] 64 5a [2] 68 50 [2] 7f 5b [2] 64 15 [2] 59 }

  condition:
    any of them
}