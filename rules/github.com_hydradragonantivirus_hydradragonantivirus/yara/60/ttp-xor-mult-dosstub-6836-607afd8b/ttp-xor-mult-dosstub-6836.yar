rule TTP_XOR_MULT_DOSStub_6836 {
  strings:
    $key_6836 = { 3c 5e [2] 48 46 [2] 0f 44 [2] 48 55 [2] 06 59 [2] 0a 53 [2] 1d 58 [2] 06 16 [2] 3b }

  condition:
    any of them
}