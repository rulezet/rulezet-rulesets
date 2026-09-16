rule TTP_XOR_MULT_DOSStub_6500 {
  strings:
    $key_6500 = { 31 68 [2] 45 70 [2] 02 72 [2] 45 63 [2] 0b 6f [2] 07 65 [2] 10 6e [2] 0b 20 [2] 36 }

  condition:
    any of them
}