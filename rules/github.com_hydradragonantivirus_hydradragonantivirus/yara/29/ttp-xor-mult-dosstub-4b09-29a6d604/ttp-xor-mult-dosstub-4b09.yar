rule TTP_XOR_MULT_DOSStub_4b09 {
  strings:
    $key_4b09 = { 1f 61 [2] 6b 79 [2] 2c 7b [2] 6b 6a [2] 25 66 [2] 29 6c [2] 3e 67 [2] 25 29 [2] 18 }

  condition:
    any of them
}