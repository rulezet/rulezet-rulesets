rule TTP_XOR_MULT_DOSStub_6f65 {
  strings:
    $key_6f65 = { 3b 0d [2] 4f 15 [2] 08 17 [2] 4f 06 [2] 01 0a [2] 0d 00 [2] 1a 0b [2] 01 45 [2] 3c }

  condition:
    any of them
}