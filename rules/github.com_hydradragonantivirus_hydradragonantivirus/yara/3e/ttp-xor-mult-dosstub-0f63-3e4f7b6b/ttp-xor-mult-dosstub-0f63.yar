rule TTP_XOR_MULT_DOSStub_0f63 {
  strings:
    $key_0f63 = { 5b 0b [2] 2f 13 [2] 68 11 [2] 2f 00 [2] 61 0c [2] 6d 06 [2] 7a 0d [2] 61 43 [2] 5c }

  condition:
    any of them
}