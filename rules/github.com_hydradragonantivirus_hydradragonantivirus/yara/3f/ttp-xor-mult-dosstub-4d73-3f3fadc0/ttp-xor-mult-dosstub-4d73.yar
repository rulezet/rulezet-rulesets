rule TTP_XOR_MULT_DOSStub_4d73 {
  strings:
    $key_4d73 = { 19 1b [2] 6d 03 [2] 2a 01 [2] 6d 10 [2] 23 1c [2] 2f 16 [2] 38 1d [2] 23 53 [2] 1e }

  condition:
    any of them
}