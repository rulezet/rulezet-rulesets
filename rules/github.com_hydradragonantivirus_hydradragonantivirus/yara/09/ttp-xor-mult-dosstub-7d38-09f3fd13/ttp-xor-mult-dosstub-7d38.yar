rule TTP_XOR_MULT_DOSStub_7d38 {
  strings:
    $key_7d38 = { 29 50 [2] 5d 48 [2] 1a 4a [2] 5d 5b [2] 13 57 [2] 1f 5d [2] 08 56 [2] 13 18 [2] 2e }

  condition:
    any of them
}