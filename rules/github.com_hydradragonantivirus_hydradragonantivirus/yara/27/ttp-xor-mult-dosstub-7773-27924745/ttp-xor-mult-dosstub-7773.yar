rule TTP_XOR_MULT_DOSStub_7773 {
  strings:
    $key_7773 = { 23 1b [2] 57 03 [2] 10 01 [2] 57 10 [2] 19 1c [2] 15 16 [2] 02 1d [2] 19 53 [2] 24 }

  condition:
    any of them
}