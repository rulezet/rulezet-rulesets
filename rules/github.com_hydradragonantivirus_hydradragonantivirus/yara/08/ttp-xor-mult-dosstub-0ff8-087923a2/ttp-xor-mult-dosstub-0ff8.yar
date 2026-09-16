rule TTP_XOR_MULT_DOSStub_0ff8 {
  strings:
    $key_0ff8 = { 5b 90 [2] 2f 88 [2] 68 8a [2] 2f 9b [2] 61 97 [2] 6d 9d [2] 7a 96 [2] 61 d8 [2] 5c }

  condition:
    any of them
}