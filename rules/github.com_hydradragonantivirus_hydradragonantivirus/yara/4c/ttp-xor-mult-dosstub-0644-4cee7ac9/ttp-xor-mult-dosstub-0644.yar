rule TTP_XOR_MULT_DOSStub_0644 {
  strings:
    $key_0644 = { 52 2c [2] 26 34 [2] 61 36 [2] 26 27 [2] 68 2b [2] 64 21 [2] 73 2a [2] 68 64 [2] 55 }

  condition:
    any of them
}