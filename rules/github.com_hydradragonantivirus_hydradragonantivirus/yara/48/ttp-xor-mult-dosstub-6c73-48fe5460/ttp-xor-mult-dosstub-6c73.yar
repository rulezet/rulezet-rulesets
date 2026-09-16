rule TTP_XOR_MULT_DOSStub_6c73 {
  strings:
    $key_6c73 = { 38 1b [2] 4c 03 [2] 0b 01 [2] 4c 10 [2] 02 1c [2] 0e 16 [2] 19 1d [2] 02 53 [2] 3f }

  condition:
    any of them
}