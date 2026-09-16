rule TTP_XOR_MULT_DOSStub_6f73 {
  strings:
    $key_6f73 = { 3b 1b [2] 4f 03 [2] 08 01 [2] 4f 10 [2] 01 1c [2] 0d 16 [2] 1a 1d [2] 01 53 [2] 3c }

  condition:
    any of them
}