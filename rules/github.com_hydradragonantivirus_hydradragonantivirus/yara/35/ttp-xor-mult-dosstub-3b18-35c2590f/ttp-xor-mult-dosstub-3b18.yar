rule TTP_XOR_MULT_DOSStub_3b18 {
  strings:
    $key_3b18 = { 6f 70 [2] 1b 68 [2] 5c 6a [2] 1b 7b [2] 55 77 [2] 59 7d [2] 4e 76 [2] 55 38 [2] 68 }

  condition:
    any of them
}