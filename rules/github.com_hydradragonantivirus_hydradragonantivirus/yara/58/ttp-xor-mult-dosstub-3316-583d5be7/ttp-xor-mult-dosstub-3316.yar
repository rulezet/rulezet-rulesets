rule TTP_XOR_MULT_DOSStub_3316 {
  strings:
    $key_3316 = { 67 7e [2] 13 66 [2] 54 64 [2] 13 75 [2] 5d 79 [2] 51 73 [2] 46 78 [2] 5d 36 [2] 60 }

  condition:
    any of them
}