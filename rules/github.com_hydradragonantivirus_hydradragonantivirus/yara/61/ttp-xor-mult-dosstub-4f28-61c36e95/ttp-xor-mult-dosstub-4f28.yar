rule TTP_XOR_MULT_DOSStub_4f28 {
  strings:
    $key_4f28 = { 1b 40 [2] 6f 58 [2] 28 5a [2] 6f 4b [2] 21 47 [2] 2d 4d [2] 3a 46 [2] 21 08 [2] 1c }

  condition:
    any of them
}