rule TTP_XOR_MULT_DOSStub_5709 {
  strings:
    $key_5709 = { 03 61 [2] 77 79 [2] 30 7b [2] 77 6a [2] 39 66 [2] 35 6c [2] 22 67 [2] 39 29 [2] 04 }

  condition:
    any of them
}