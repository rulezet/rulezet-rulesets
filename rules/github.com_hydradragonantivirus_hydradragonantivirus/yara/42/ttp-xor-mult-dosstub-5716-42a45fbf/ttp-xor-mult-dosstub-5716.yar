rule TTP_XOR_MULT_DOSStub_5716 {
  strings:
    $key_5716 = { 03 7e [2] 77 66 [2] 30 64 [2] 77 75 [2] 39 79 [2] 35 73 [2] 22 78 [2] 39 36 [2] 04 }

  condition:
    any of them
}