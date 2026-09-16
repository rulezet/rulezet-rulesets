rule TTP_XOR_MULT_DOSStub_0e64 {
  strings:
    $key_0e64 = { 5a 0c [2] 2e 14 [2] 69 16 [2] 2e 07 [2] 60 0b [2] 6c 01 [2] 7b 0a [2] 60 44 [2] 5d }

  condition:
    any of them
}