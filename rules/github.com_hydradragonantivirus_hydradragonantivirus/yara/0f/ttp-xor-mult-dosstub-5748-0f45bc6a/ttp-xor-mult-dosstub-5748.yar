rule TTP_XOR_MULT_DOSStub_5748 {
  strings:
    $key_5748 = { 03 20 [2] 77 38 [2] 30 3a [2] 77 2b [2] 39 27 [2] 35 2d [2] 22 26 [2] 39 68 [2] 04 }

  condition:
    any of them
}