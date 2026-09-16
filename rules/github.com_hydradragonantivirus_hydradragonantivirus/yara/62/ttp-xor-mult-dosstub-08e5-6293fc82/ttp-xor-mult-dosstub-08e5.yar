rule TTP_XOR_MULT_DOSStub_08e5 {
  strings:
    $key_08e5 = { 5c 8d [2] 28 95 [2] 6f 97 [2] 28 86 [2] 66 8a [2] 6a 80 [2] 7d 8b [2] 66 c5 [2] 5b }

  condition:
    any of them
}