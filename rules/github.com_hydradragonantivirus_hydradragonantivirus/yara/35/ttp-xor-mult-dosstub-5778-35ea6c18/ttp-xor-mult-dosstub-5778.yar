rule TTP_XOR_MULT_DOSStub_5778 {
  strings:
    $key_5778 = { 03 10 [2] 77 08 [2] 30 0a [2] 77 1b [2] 39 17 [2] 35 1d [2] 22 16 [2] 39 58 [2] 04 }

  condition:
    any of them
}