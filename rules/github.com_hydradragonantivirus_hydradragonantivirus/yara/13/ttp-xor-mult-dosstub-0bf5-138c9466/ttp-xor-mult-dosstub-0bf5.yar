rule TTP_XOR_MULT_DOSStub_0bf5 {
  strings:
    $key_0bf5 = { 5f 9d [2] 2b 85 [2] 6c 87 [2] 2b 96 [2] 65 9a [2] 69 90 [2] 7e 9b [2] 65 d5 [2] 58 }

  condition:
    any of them
}