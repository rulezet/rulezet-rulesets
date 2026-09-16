rule TTP_XOR_MULT_DOSStub_5e64 {
  strings:
    $key_5e64 = { 0a 0c [2] 7e 14 [2] 39 16 [2] 7e 07 [2] 30 0b [2] 3c 01 [2] 2b 0a [2] 30 44 [2] 0d }

  condition:
    any of them
}