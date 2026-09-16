rule TTP_XOR_MULT_DOSStub_0016 {
  strings:
    $key_0016 = { 54 7e [2] 20 66 [2] 67 64 [2] 20 75 [2] 6e 79 [2] 62 73 [2] 75 78 [2] 6e 36 [2] 53 }

  condition:
    any of them
}