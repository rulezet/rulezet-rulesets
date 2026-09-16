rule TTP_XOR_MULT_DOSStub_ffc1 {
  strings:
    $key_ffc1 = { ab a9 [2] df b1 [2] 98 b3 [2] df a2 [2] 91 ae [2] 9d a4 [2] 8a af [2] 91 e1 [2] ac }

  condition:
    any of them
}