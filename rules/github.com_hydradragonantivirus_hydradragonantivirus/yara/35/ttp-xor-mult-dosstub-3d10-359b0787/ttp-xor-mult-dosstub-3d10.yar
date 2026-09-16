rule TTP_XOR_MULT_DOSStub_3d10 {
  strings:
    $key_3d10 = { 69 78 [2] 1d 60 [2] 5a 62 [2] 1d 73 [2] 53 7f [2] 5f 75 [2] 48 7e [2] 53 30 [2] 6e }

  condition:
    any of them
}