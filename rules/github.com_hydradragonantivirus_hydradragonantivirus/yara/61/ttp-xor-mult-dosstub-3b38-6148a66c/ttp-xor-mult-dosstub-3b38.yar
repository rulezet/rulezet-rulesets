rule TTP_XOR_MULT_DOSStub_3b38 {
  strings:
    $key_3b38 = { 6f 50 [2] 1b 48 [2] 5c 4a [2] 1b 5b [2] 55 57 [2] 59 5d [2] 4e 56 [2] 55 18 [2] 68 }

  condition:
    any of them
}