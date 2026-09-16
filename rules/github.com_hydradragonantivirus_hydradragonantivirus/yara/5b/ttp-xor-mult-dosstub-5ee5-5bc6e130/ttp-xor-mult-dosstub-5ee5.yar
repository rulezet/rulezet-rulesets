rule TTP_XOR_MULT_DOSStub_5ee5 {
  strings:
    $key_5ee5 = { 0a 8d [2] 7e 95 [2] 39 97 [2] 7e 86 [2] 30 8a [2] 3c 80 [2] 2b 8b [2] 30 c5 [2] 0d }

  condition:
    any of them
}