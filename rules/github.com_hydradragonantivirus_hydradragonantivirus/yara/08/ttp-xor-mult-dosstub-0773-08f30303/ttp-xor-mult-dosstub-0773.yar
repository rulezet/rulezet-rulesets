rule TTP_XOR_MULT_DOSStub_0773 {
  strings:
    $key_0773 = { 53 1b [2] 27 03 [2] 60 01 [2] 27 10 [2] 69 1c [2] 65 16 [2] 72 1d [2] 69 53 [2] 54 }

  condition:
    any of them
}