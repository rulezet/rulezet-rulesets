rule TTP_XOR_MULT_DOSStub_6f79 {
  strings:
    $key_6f79 = { 3b 11 [2] 4f 09 [2] 08 0b [2] 4f 1a [2] 01 16 [2] 0d 1c [2] 1a 17 [2] 01 59 [2] 3c }

  condition:
    any of them
}