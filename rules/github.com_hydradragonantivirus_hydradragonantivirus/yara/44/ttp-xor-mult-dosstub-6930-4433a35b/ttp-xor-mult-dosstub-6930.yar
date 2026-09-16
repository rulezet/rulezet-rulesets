rule TTP_XOR_MULT_DOSStub_6930 {
  strings:
    $key_6930 = { 3d 58 [2] 49 40 [2] 0e 42 [2] 49 53 [2] 07 5f [2] 0b 55 [2] 1c 5e [2] 07 10 [2] 3a }

  condition:
    any of them
}