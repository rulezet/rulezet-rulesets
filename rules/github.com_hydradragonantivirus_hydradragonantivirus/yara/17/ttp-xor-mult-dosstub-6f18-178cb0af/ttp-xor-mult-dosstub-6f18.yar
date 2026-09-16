rule TTP_XOR_MULT_DOSStub_6f18 {
  strings:
    $key_6f18 = { 3b 70 [2] 4f 68 [2] 08 6a [2] 4f 7b [2] 01 77 [2] 0d 7d [2] 1a 76 [2] 01 38 [2] 3c }

  condition:
    any of them
}