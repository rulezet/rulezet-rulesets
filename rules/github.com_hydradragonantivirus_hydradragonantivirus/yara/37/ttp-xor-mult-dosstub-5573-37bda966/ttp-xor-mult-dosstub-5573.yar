rule TTP_XOR_MULT_DOSStub_5573 {
  strings:
    $key_5573 = { 01 1b [2] 75 03 [2] 32 01 [2] 75 10 [2] 3b 1c [2] 37 16 [2] 20 1d [2] 3b 53 [2] 06 }

  condition:
    any of them
}