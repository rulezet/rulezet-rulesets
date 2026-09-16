rule TTP_XOR_MULT_DOSStub_3810 {
  strings:
    $key_3810 = { 6c 78 [2] 18 60 [2] 5f 62 [2] 18 73 [2] 56 7f [2] 5a 75 [2] 4d 7e [2] 56 30 [2] 6b }

  condition:
    any of them
}