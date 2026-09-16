rule TTP_XOR_MULT_DOSStub_5775 {
  strings:
    $key_5775 = { 03 1d [2] 77 05 [2] 30 07 [2] 77 16 [2] 39 1a [2] 35 10 [2] 22 1b [2] 39 55 [2] 04 }

  condition:
    any of them
}