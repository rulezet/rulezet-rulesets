rule TTP_XOR_MULT_DOSStub_32a8 {
  strings:
    $key_32a8 = { 66 c0 [2] 12 d8 [2] 55 da [2] 12 cb [2] 5c c7 [2] 50 cd [2] 47 c6 [2] 5c 88 [2] 61 }

  condition:
    any of them
}