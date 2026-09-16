rule TTP_XOR_MULT_DOSStub_0f44 {
  strings:
    $key_0f44 = { 5b 2c [2] 2f 34 [2] 68 36 [2] 2f 27 [2] 61 2b [2] 6d 21 [2] 7a 2a [2] 61 64 [2] 5c }

  condition:
    any of them
}