rule TTP_XOR_MULT_DOSStub_4830 {
  strings:
    $key_4830 = { 1c 58 [2] 68 40 [2] 2f 42 [2] 68 53 [2] 26 5f [2] 2a 55 [2] 3d 5e [2] 26 10 [2] 1b }

  condition:
    any of them
}