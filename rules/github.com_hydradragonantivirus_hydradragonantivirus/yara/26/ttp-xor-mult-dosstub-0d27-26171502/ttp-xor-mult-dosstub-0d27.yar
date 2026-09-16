rule TTP_XOR_MULT_DOSStub_0d27 {
  strings:
    $key_0d27 = { 59 4f [2] 2d 57 [2] 6a 55 [2] 2d 44 [2] 63 48 [2] 6f 42 [2] 78 49 [2] 63 07 [2] 5e }

  condition:
    any of them
}