rule TTP_XOR_MULT_DOSStub_3bf5 {
  strings:
    $key_3bf5 = { 6f 9d [2] 1b 85 [2] 5c 87 [2] 1b 96 [2] 55 9a [2] 59 90 [2] 4e 9b [2] 55 d5 [2] 68 }

  condition:
    any of them
}