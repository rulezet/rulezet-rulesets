rule TTP_XOR_MULT_DOSStub_5ef5 {
  strings:
    $key_5ef5 = { 0a 9d [2] 7e 85 [2] 39 87 [2] 7e 96 [2] 30 9a [2] 3c 90 [2] 2b 9b [2] 30 d5 [2] 0d }

  condition:
    any of them
}