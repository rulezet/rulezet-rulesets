rule TTP_XOR_MULT_DOSStub_3b14 {
  strings:
    $key_3b14 = { 6f 7c [2] 1b 64 [2] 5c 66 [2] 1b 77 [2] 55 7b [2] 59 71 [2] 4e 7a [2] 55 34 [2] 68 }

  condition:
    any of them
}