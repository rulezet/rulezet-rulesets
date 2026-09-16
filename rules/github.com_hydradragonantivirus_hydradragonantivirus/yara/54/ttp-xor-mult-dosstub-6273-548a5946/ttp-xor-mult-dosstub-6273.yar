rule TTP_XOR_MULT_DOSStub_6273 {
  strings:
    $key_6273 = { 36 1b [2] 42 03 [2] 05 01 [2] 42 10 [2] 0c 1c [2] 00 16 [2] 17 1d [2] 0c 53 [2] 31 }

  condition:
    any of them
}