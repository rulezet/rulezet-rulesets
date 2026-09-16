rule TTP_XOR_MULT_DOSStub_0f73 {
  strings:
    $key_0f73 = { 5b 1b [2] 2f 03 [2] 68 01 [2] 2f 10 [2] 61 1c [2] 6d 16 [2] 7a 1d [2] 61 53 [2] 5c }

  condition:
    any of them
}