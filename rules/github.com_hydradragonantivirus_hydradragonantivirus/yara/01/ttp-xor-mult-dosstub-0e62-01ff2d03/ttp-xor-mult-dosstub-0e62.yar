rule TTP_XOR_MULT_DOSStub_0e62 {
  strings:
    $key_0e62 = { 5a 0a [2] 2e 12 [2] 69 10 [2] 2e 01 [2] 60 0d [2] 6c 07 [2] 7b 0c [2] 60 42 [2] 5d }

  condition:
    any of them
}