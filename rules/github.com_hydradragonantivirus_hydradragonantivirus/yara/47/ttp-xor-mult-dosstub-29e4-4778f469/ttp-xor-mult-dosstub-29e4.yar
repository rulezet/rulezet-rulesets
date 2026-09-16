rule TTP_XOR_MULT_DOSStub_29e4 {
  strings:
    $key_29e4 = { 7d 8c [2] 09 94 [2] 4e 96 [2] 09 87 [2] 47 8b [2] 4b 81 [2] 5c 8a [2] 47 c4 [2] 7a }

  condition:
    any of them
}