rule TTP_XOR_MULT_DOSStub_6560 {
  strings:
    $key_6560 = { 31 08 [2] 45 10 [2] 02 12 [2] 45 03 [2] 0b 0f [2] 07 05 [2] 10 0e [2] 0b 40 [2] 36 }

  condition:
    any of them
}