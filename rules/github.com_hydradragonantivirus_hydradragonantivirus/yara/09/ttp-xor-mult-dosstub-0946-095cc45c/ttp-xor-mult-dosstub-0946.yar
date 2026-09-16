rule TTP_XOR_MULT_DOSStub_0946 {
  strings:
    $key_0946 = { 5d 2e [2] 29 36 [2] 6e 34 [2] 29 25 [2] 67 29 [2] 6b 23 [2] 7c 28 [2] 67 66 [2] 5a }

  condition:
    any of them
}