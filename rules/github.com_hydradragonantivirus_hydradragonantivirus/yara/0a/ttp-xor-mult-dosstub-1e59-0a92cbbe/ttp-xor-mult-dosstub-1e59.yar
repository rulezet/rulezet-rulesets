rule TTP_XOR_MULT_DOSStub_1e59 {
  strings:
    $key_1e59 = { 4a 31 [2] 3e 29 [2] 79 2b [2] 3e 3a [2] 70 36 [2] 7c 3c [2] 6b 37 [2] 70 79 [2] 4d }

  condition:
    any of them
}