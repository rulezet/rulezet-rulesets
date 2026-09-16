rule TTP_XOR_MULT_DOSStub_0f10 {
  strings:
    $key_0f10 = { 5b 78 [2] 2f 60 [2] 68 62 [2] 2f 73 [2] 61 7f [2] 6d 75 [2] 7a 7e [2] 61 30 [2] 5c }

  condition:
    any of them
}