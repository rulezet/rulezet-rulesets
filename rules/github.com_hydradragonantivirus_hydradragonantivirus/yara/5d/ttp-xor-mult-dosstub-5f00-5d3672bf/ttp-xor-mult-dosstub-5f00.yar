rule TTP_XOR_MULT_DOSStub_5f00 {
  strings:
    $key_5f00 = { 0b 68 [2] 7f 70 [2] 38 72 [2] 7f 63 [2] 31 6f [2] 3d 65 [2] 2a 6e [2] 31 20 [2] 0c }

  condition:
    any of them
}