rule TTP_XOR_MULT_DOSStub_1f63 {
  strings:
    $key_1f63 = { 4b 0b [2] 3f 13 [2] 78 11 [2] 3f 00 [2] 71 0c [2] 7d 06 [2] 6a 0d [2] 71 43 [2] 4c }

  condition:
    any of them
}