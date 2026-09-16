rule TTP_XOR_MULT_DOSStub_6f14 {
  strings:
    $key_6f14 = { 3b 7c [2] 4f 64 [2] 08 66 [2] 4f 77 [2] 01 7b [2] 0d 71 [2] 1a 7a [2] 01 34 [2] 3c }

  condition:
    any of them
}