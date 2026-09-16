rule TTP_XOR_MULT_DOSStub_327a {
  strings:
    $key_327a = { 66 12 [2] 12 0a [2] 55 08 [2] 12 19 [2] 5c 15 [2] 50 1f [2] 47 14 [2] 5c 5a [2] 61 }

  condition:
    any of them
}