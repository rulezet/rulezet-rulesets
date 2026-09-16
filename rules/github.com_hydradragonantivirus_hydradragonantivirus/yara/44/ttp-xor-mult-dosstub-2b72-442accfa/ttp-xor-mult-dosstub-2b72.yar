rule TTP_XOR_MULT_DOSStub_2b72 {
  strings:
    $key_2b72 = { 7f 1a [2] 0b 02 [2] 4c 00 [2] 0b 11 [2] 45 1d [2] 49 17 [2] 5e 1c [2] 45 52 [2] 78 }

  condition:
    any of them
}