rule TTP_XOR_MULT_DOSStub_2b75 {
  strings:
    $key_2b75 = { 7f 1d [2] 0b 05 [2] 4c 07 [2] 0b 16 [2] 45 1a [2] 49 10 [2] 5e 1b [2] 45 55 [2] 78 }

  condition:
    any of them
}