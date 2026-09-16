rule TTP_XOR_MULT_DOSStub_5704 {
  strings:
    $key_5704 = { 03 6c [2] 77 74 [2] 30 76 [2] 77 67 [2] 39 6b [2] 35 61 [2] 22 6a [2] 39 24 [2] 04 }

  condition:
    any of them
}