rule TTP_XOR_MULT_DOSStub_6ff8 {
  strings:
    $key_6ff8 = { 3b 90 [2] 4f 88 [2] 08 8a [2] 4f 9b [2] 01 97 [2] 0d 9d [2] 1a 96 [2] 01 d8 [2] 3c }

  condition:
    any of them
}