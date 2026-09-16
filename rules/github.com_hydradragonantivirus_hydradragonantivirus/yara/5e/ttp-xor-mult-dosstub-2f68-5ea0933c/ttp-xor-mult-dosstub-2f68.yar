rule TTP_XOR_MULT_DOSStub_2f68 {
  strings:
    $key_2f68 = { 7b 00 [2] 0f 18 [2] 48 1a [2] 0f 0b [2] 41 07 [2] 4d 0d [2] 5a 06 [2] 41 48 [2] 7c }

  condition:
    any of them
}