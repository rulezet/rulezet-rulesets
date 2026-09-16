rule TTP_XOR_MULT_DOSStub_6c23 {
  strings:
    $key_6c23 = { 38 4b [2] 4c 53 [2] 0b 51 [2] 4c 40 [2] 02 4c [2] 0e 46 [2] 19 4d [2] 02 03 [2] 3f }

  condition:
    any of them
}