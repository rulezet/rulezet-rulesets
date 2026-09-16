rule TTP_XOR_MULT_DOSStub_7915 {
  strings:
    $key_7915 = { 2d 7d [2] 59 65 [2] 1e 67 [2] 59 76 [2] 17 7a [2] 1b 70 [2] 0c 7b [2] 17 35 [2] 2a }

  condition:
    any of them
}