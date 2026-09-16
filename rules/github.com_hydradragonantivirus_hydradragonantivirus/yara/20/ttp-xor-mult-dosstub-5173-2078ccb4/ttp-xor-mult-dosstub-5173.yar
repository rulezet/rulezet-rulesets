rule TTP_XOR_MULT_DOSStub_5173 {
  strings:
    $key_5173 = { 05 1b [2] 71 03 [2] 36 01 [2] 71 10 [2] 3f 1c [2] 33 16 [2] 24 1d [2] 3f 53 [2] 02 }

  condition:
    any of them
}