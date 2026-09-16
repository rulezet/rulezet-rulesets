rule TTP_XOR_MULT_DOSStub_0d61 {
  strings:
    $key_0d61 = { 59 09 [2] 2d 11 [2] 6a 13 [2] 2d 02 [2] 63 0e [2] 6f 04 [2] 78 0f [2] 63 41 [2] 5e }

  condition:
    any of them
}