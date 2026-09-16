rule TTP_XOR_MULT_DOSStub_6810 {
  strings:
    $key_6810 = { 3c 78 [2] 48 60 [2] 0f 62 [2] 48 73 [2] 06 7f [2] 0a 75 [2] 1d 7e [2] 06 30 [2] 3b }

  condition:
    any of them
}