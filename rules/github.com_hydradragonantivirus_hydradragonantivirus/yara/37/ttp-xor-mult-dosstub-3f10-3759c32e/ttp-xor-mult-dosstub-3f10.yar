rule TTP_XOR_MULT_DOSStub_3f10 {
  strings:
    $key_3f10 = { 6b 78 [2] 1f 60 [2] 58 62 [2] 1f 73 [2] 51 7f [2] 5d 75 [2] 4a 7e [2] 51 30 [2] 6c }

  condition:
    any of them
}