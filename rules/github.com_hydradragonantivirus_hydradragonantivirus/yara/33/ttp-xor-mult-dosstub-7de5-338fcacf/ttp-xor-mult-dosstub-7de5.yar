rule TTP_XOR_MULT_DOSStub_7de5 {
  strings:
    $key_7de5 = { 29 8d [2] 5d 95 [2] 1a 97 [2] 5d 86 [2] 13 8a [2] 1f 80 [2] 08 8b [2] 13 c5 [2] 2e }

  condition:
    any of them
}