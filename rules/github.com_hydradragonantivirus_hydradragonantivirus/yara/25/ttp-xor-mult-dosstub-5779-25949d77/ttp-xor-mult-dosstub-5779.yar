rule TTP_XOR_MULT_DOSStub_5779 {
  strings:
    $key_5779 = { 03 11 [2] 77 09 [2] 30 0b [2] 77 1a [2] 39 16 [2] 35 1c [2] 22 17 [2] 39 59 [2] 04 }

  condition:
    any of them
}