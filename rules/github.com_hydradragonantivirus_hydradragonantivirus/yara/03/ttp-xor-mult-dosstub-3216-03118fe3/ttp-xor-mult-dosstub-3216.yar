rule TTP_XOR_MULT_DOSStub_3216 {
  strings:
    $key_3216 = { 66 7e [2] 12 66 [2] 55 64 [2] 12 75 [2] 5c 79 [2] 50 73 [2] 47 78 [2] 5c 36 [2] 61 }

  condition:
    any of them
}