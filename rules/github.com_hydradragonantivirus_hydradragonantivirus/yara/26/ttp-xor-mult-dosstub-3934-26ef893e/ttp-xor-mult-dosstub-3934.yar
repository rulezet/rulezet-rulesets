rule TTP_XOR_MULT_DOSStub_3934 {
  strings:
    $key_3934 = { 6d 5c [2] 19 44 [2] 5e 46 [2] 19 57 [2] 57 5b [2] 5b 51 [2] 4c 5a [2] 57 14 [2] 6a }

  condition:
    any of them
}