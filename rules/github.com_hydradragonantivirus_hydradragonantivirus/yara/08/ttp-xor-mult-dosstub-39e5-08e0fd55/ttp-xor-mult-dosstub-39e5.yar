rule TTP_XOR_MULT_DOSStub_39e5 {
  strings:
    $key_39e5 = { 6d 8d [2] 19 95 [2] 5e 97 [2] 19 86 [2] 57 8a [2] 5b 80 [2] 4c 8b [2] 57 c5 [2] 6a }

  condition:
    any of them
}