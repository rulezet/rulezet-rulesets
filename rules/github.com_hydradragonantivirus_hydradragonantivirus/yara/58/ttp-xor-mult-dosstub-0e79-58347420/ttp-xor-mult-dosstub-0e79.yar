rule TTP_XOR_MULT_DOSStub_0e79 {
  strings:
    $key_0e79 = { 5a 11 [2] 2e 09 [2] 69 0b [2] 2e 1a [2] 60 16 [2] 6c 1c [2] 7b 17 [2] 60 59 [2] 5d }

  condition:
    any of them
}