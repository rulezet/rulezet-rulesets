rule TTP_XOR_MULT_DOSStub_2579 {
  strings:
    $key_2579 = { 71 11 [2] 05 09 [2] 42 0b [2] 05 1a [2] 4b 16 [2] 47 1c [2] 50 17 [2] 4b 59 [2] 76 }

  condition:
    any of them
}