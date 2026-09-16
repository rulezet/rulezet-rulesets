rule TTP_XOR_MULT_DOSStub_6e00 {
  strings:
    $key_6e00 = { 3a 68 [2] 4e 70 [2] 09 72 [2] 4e 63 [2] 00 6f [2] 0c 65 [2] 1b 6e [2] 00 20 [2] 3d }

  condition:
    any of them
}