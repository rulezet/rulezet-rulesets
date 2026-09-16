rule TTP_XOR_MULT_DOSStub_6d10 {
  strings:
    $key_6d10 = { 39 78 [2] 4d 60 [2] 0a 62 [2] 4d 73 [2] 03 7f [2] 0f 75 [2] 18 7e [2] 03 30 [2] 3e }

  condition:
    any of them
}