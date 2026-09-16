rule TTP_XOR_MULT_DOSStub_5f10 {
  strings:
    $key_5f10 = { 0b 78 [2] 7f 60 [2] 38 62 [2] 7f 73 [2] 31 7f [2] 3d 75 [2] 2a 7e [2] 31 30 [2] 0c }

  condition:
    any of them
}