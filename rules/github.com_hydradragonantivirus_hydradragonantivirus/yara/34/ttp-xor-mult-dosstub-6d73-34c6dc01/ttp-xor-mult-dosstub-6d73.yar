rule TTP_XOR_MULT_DOSStub_6d73 {
  strings:
    $key_6d73 = { 39 1b [2] 4d 03 [2] 0a 01 [2] 4d 10 [2] 03 1c [2] 0f 16 [2] 18 1d [2] 03 53 [2] 3e }

  condition:
    any of them
}