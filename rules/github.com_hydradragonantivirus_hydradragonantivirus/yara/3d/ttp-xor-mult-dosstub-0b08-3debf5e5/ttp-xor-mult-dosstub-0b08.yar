rule TTP_XOR_MULT_DOSStub_0b08 {
  strings:
    $key_0b08 = { 5f 60 [2] 2b 78 [2] 6c 7a [2] 2b 6b [2] 65 67 [2] 69 6d [2] 7e 66 [2] 65 28 [2] 58 }

  condition:
    any of them
}