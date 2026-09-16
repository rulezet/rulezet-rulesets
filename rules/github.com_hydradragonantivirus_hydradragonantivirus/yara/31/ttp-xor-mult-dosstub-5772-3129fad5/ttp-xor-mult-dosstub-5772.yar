rule TTP_XOR_MULT_DOSStub_5772 {
  strings:
    $key_5772 = { 03 1a [2] 77 02 [2] 30 00 [2] 77 11 [2] 39 1d [2] 35 17 [2] 22 1c [2] 39 52 [2] 04 }

  condition:
    any of them
}