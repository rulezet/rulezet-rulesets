rule TTP_XOR_MULT_DOSStub_0a52 {
  strings:
    $key_0a52 = { 5e 3a [2] 2a 22 [2] 6d 20 [2] 2a 31 [2] 64 3d [2] 68 37 [2] 7f 3c [2] 64 72 [2] 59 }

  condition:
    any of them
}