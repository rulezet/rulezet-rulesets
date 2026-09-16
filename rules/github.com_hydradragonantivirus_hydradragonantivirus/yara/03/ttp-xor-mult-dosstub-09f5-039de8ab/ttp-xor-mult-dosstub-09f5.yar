rule TTP_XOR_MULT_DOSStub_09f5 {
  strings:
    $key_09f5 = { 5d 9d [2] 29 85 [2] 6e 87 [2] 29 96 [2] 67 9a [2] 6b 90 [2] 7c 9b [2] 67 d5 [2] 5a }

  condition:
    any of them
}