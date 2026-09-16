rule TTP_XOR_MULT_DOSStub_6531 {
  strings:
    $key_6531 = { 31 59 [2] 45 41 [2] 02 43 [2] 45 52 [2] 0b 5e [2] 07 54 [2] 10 5f [2] 0b 11 [2] 36 }

  condition:
    any of them
}