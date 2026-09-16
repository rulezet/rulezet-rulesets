rule TTP_XOR_MULT_DOSStub_0916 {
  strings:
    $key_0916 = { 5d 7e [2] 29 66 [2] 6e 64 [2] 29 75 [2] 67 79 [2] 6b 73 [2] 7c 78 [2] 67 36 [2] 5a }

  condition:
    any of them
}