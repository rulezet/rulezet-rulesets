rule TTP_XOR_MULT_DOSStub_3d11 {
  strings:
    $key_3d11 = { 69 79 [2] 1d 61 [2] 5a 63 [2] 1d 72 [2] 53 7e [2] 5f 74 [2] 48 7f [2] 53 31 [2] 6e }

  condition:
    any of them
}