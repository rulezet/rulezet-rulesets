rule TTP_XOR_MULT_DOSStub_6522 {
  strings:
    $key_6522 = { 31 4a [2] 45 52 [2] 02 50 [2] 45 41 [2] 0b 4d [2] 07 47 [2] 10 4c [2] 0b 02 [2] 36 }

  condition:
    any of them
}