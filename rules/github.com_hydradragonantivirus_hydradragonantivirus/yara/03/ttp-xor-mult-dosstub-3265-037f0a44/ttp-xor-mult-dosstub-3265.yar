rule TTP_XOR_MULT_DOSStub_3265 {
  strings:
    $key_3265 = { 66 0d [2] 12 15 [2] 55 17 [2] 12 06 [2] 5c 0a [2] 50 00 [2] 47 0b [2] 5c 45 [2] 61 }

  condition:
    any of them
}