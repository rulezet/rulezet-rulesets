rule TTP_XOR_MULT_DOSStub_4d10 {
  strings:
    $key_4d10 = { 19 78 [2] 6d 60 [2] 2a 62 [2] 6d 73 [2] 23 7f [2] 2f 75 [2] 38 7e [2] 23 30 [2] 1e }

  condition:
    any of them
}