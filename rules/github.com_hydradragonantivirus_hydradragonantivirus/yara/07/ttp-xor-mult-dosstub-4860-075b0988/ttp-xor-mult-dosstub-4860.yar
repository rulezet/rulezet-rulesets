rule TTP_XOR_MULT_DOSStub_4860 {
  strings:
    $key_4860 = { 1c 08 [2] 68 10 [2] 2f 12 [2] 68 03 [2] 26 0f [2] 2a 05 [2] 3d 0e [2] 26 40 [2] 1b }

  condition:
    any of them
}