rule TTP_XOR_MULT_DOSStub_2a25 {
  strings:
    $key_2a25 = { 7e 4d [2] 0a 55 [2] 4d 57 [2] 0a 46 [2] 44 4a [2] 48 40 [2] 5f 4b [2] 44 05 [2] 79 }

  condition:
    any of them
}