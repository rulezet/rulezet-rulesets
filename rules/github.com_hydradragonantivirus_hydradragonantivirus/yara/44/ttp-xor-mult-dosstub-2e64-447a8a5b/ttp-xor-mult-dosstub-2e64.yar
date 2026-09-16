rule TTP_XOR_MULT_DOSStub_2e64 {
  strings:
    $key_2e64 = { 7a 0c [2] 0e 14 [2] 49 16 [2] 0e 07 [2] 40 0b [2] 4c 01 [2] 5b 0a [2] 40 44 [2] 7d }

  condition:
    any of them
}