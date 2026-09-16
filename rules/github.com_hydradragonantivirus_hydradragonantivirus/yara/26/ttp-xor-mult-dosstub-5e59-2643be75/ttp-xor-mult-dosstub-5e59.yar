rule TTP_XOR_MULT_DOSStub_5e59 {
  strings:
    $key_5e59 = { 0a 31 [2] 7e 29 [2] 39 2b [2] 7e 3a [2] 30 36 [2] 3c 3c [2] 2b 37 [2] 30 79 [2] 0d }

  condition:
    any of them
}