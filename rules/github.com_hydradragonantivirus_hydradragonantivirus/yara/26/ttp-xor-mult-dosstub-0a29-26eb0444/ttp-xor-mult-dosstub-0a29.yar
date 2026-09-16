rule TTP_XOR_MULT_DOSStub_0a29 {
  strings:
    $key_0a29 = { 5e 41 [2] 2a 59 [2] 6d 5b [2] 2a 4a [2] 64 46 [2] 68 4c [2] 7f 47 [2] 64 09 [2] 59 }

  condition:
    any of them
}