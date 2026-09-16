rule TTP_XOR_MULT_DOSStub_0d10 {
  strings:
    $key_0d10 = { 59 78 [2] 2d 60 [2] 6a 62 [2] 2d 73 [2] 63 7f [2] 6f 75 [2] 78 7e [2] 63 30 [2] 5e }

  condition:
    any of them
}