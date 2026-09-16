rule TTP_XOR_MULT_DOSStub_2053 {
  strings:
    $key_2053 = { 74 3b [2] 00 23 [2] 47 21 [2] 00 30 [2] 4e 3c [2] 42 36 [2] 55 3d [2] 4e 73 [2] 73 }

  condition:
    any of them
}