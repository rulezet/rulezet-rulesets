rule TTP_XOR_MULT_DOSStub_2073 {
  strings:
    $key_2073 = { 74 1b [2] 00 03 [2] 47 01 [2] 00 10 [2] 4e 1c [2] 42 16 [2] 55 1d [2] 4e 53 [2] 73 }

  condition:
    any of them
}