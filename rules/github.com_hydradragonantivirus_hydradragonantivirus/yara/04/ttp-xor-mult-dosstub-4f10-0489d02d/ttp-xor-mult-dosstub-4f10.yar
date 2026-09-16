rule TTP_XOR_MULT_DOSStub_4f10 {
  strings:
    $key_4f10 = { 1b 78 [2] 6f 60 [2] 28 62 [2] 6f 73 [2] 21 7f [2] 2d 75 [2] 3a 7e [2] 21 30 [2] 1c }

  condition:
    any of them
}