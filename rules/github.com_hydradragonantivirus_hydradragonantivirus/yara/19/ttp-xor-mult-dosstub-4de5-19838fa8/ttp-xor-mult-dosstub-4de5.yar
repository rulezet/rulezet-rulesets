rule TTP_XOR_MULT_DOSStub_4de5 {
  strings:
    $key_4de5 = { 19 8d [2] 6d 95 [2] 2a 97 [2] 6d 86 [2] 23 8a [2] 2f 80 [2] 38 8b [2] 23 c5 [2] 1e }

  condition:
    any of them
}