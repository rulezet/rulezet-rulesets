rule TTP_XOR_MULT_DOSStub_0938 {
  strings:
    $key_0938 = { 5d 50 [2] 29 48 [2] 6e 4a [2] 29 5b [2] 67 57 [2] 6b 5d [2] 7c 56 [2] 67 18 [2] 5a }

  condition:
    any of them
}