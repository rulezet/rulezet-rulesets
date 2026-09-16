rule TTP_XOR_MULT_DOSStub_0d67 {
  strings:
    $key_0d67 = { 59 0f [2] 2d 17 [2] 6a 15 [2] 2d 04 [2] 63 08 [2] 6f 02 [2] 78 09 [2] 63 47 [2] 5e }

  condition:
    any of them
}