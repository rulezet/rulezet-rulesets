rule TTP_XOR_MULT_DOSStub_6f28 {
  strings:
    $key_6f28 = { 3b 40 [2] 4f 58 [2] 08 5a [2] 4f 4b [2] 01 47 [2] 0d 4d [2] 1a 46 [2] 01 08 [2] 3c }

  condition:
    any of them
}