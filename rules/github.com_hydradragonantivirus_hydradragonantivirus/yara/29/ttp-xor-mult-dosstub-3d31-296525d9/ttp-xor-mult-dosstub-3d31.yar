rule TTP_XOR_MULT_DOSStub_3d31 {
  strings:
    $key_3d31 = { 69 59 [2] 1d 41 [2] 5a 43 [2] 1d 52 [2] 53 5e [2] 5f 54 [2] 48 5f [2] 53 11 [2] 6e }

  condition:
    any of them
}