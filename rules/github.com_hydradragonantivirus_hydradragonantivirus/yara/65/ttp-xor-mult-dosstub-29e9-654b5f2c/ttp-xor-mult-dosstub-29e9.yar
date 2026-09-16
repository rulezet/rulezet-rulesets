rule TTP_XOR_MULT_DOSStub_29e9 {
  strings:
    $key_29e9 = { 7d 81 [2] 09 99 [2] 4e 9b [2] 09 8a [2] 47 86 [2] 4b 8c [2] 5c 87 [2] 47 c9 [2] 7a }

  condition:
    any of them
}