rule TTP_XOR_MULT_DOSStub_6502 {
  strings:
    $key_6502 = { 31 6a [2] 45 72 [2] 02 70 [2] 45 61 [2] 0b 6d [2] 07 67 [2] 10 6c [2] 0b 22 [2] 36 }

  condition:
    any of them
}