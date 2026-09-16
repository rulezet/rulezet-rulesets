rule TTP_XOR_MULT_DOSStub_5e04 {
  strings:
    $key_5e04 = { 0a 6c [2] 7e 74 [2] 39 76 [2] 7e 67 [2] 30 6b [2] 3c 61 [2] 2b 6a [2] 30 24 [2] 0d }

  condition:
    any of them
}