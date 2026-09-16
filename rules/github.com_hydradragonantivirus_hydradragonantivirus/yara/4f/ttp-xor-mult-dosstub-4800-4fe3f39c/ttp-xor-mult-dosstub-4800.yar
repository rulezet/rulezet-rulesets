rule TTP_XOR_MULT_DOSStub_4800 {
  strings:
    $key_4800 = { 1c 68 [2] 68 70 [2] 2f 72 [2] 68 63 [2] 26 6f [2] 2a 65 [2] 3d 6e [2] 26 20 [2] 1b }

  condition:
    any of them
}