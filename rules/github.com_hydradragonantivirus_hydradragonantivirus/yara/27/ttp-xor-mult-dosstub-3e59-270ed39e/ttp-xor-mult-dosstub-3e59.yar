rule TTP_XOR_MULT_DOSStub_3e59 {
  strings:
    $key_3e59 = { 6a 31 [2] 1e 29 [2] 59 2b [2] 1e 3a [2] 50 36 [2] 5c 3c [2] 4b 37 [2] 50 79 [2] 6d }

  condition:
    any of them
}