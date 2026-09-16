rule TTP_XOR_MULT_DOSStub_6511 {
  strings:
    $key_6511 = { 31 79 [2] 45 61 [2] 02 63 [2] 45 72 [2] 0b 7e [2] 07 74 [2] 10 7f [2] 0b 31 [2] 36 }

  condition:
    any of them
}