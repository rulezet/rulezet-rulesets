rule TTP_XOR_MULT_DOSStub_0a16 {
  strings:
    $key_0a16 = { 5e 7e [2] 2a 66 [2] 6d 64 [2] 2a 75 [2] 64 79 [2] 68 73 [2] 7f 78 [2] 64 36 [2] 59 }

  condition:
    any of them
}