rule TTP_XOR_MULT_DOSStub_0a17 {
  strings:
    $key_0a17 = { 5e 7f [2] 2a 67 [2] 6d 65 [2] 2a 74 [2] 64 78 [2] 68 72 [2] 7f 79 [2] 64 37 [2] 59 }

  condition:
    any of them
}