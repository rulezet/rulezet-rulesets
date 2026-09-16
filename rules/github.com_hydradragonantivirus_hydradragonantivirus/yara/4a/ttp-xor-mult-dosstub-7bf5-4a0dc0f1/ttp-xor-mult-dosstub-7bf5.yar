rule TTP_XOR_MULT_DOSStub_7bf5 {
  strings:
    $key_7bf5 = { 2f 9d [2] 5b 85 [2] 1c 87 [2] 5b 96 [2] 15 9a [2] 19 90 [2] 0e 9b [2] 15 d5 [2] 28 }

  condition:
    any of them
}