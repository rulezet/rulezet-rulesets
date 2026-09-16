rule TTP_XOR_MULT_DOSStub_62a8 {
  strings:
    $key_62a8 = { 36 c0 [2] 42 d8 [2] 05 da [2] 42 cb [2] 0c c7 [2] 00 cd [2] 17 c6 [2] 0c 88 [2] 31 }

  condition:
    any of them
}