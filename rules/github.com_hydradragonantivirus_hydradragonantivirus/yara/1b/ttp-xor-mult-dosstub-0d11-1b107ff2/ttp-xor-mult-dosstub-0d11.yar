rule TTP_XOR_MULT_DOSStub_0d11 {
  strings:
    $key_0d11 = { 59 79 [2] 2d 61 [2] 6a 63 [2] 2d 72 [2] 63 7e [2] 6f 74 [2] 78 7f [2] 63 31 [2] 5e }

  condition:
    any of them
}