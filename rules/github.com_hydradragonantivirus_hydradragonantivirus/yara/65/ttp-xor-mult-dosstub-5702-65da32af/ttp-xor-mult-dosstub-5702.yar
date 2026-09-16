rule TTP_XOR_MULT_DOSStub_5702 {
  strings:
    $key_5702 = { 03 6a [2] 77 72 [2] 30 70 [2] 77 61 [2] 39 6d [2] 35 67 [2] 22 6c [2] 39 22 [2] 04 }

  condition:
    any of them
}