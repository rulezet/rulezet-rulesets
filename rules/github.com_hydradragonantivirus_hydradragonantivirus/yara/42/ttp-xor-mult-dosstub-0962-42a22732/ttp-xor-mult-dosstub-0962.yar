rule TTP_XOR_MULT_DOSStub_0962 {
  strings:
    $key_0962 = { 5d 0a [2] 29 12 [2] 6e 10 [2] 29 01 [2] 67 0d [2] 6b 07 [2] 7c 0c [2] 67 42 [2] 5a }

  condition:
    any of them
}