rule TTP_XOR_MULT_DOSStub_5d73 {
  strings:
    $key_5d73 = { 09 1b [2] 7d 03 [2] 3a 01 [2] 7d 10 [2] 33 1c [2] 3f 16 [2] 28 1d [2] 33 53 [2] 0e }

  condition:
    any of them
}