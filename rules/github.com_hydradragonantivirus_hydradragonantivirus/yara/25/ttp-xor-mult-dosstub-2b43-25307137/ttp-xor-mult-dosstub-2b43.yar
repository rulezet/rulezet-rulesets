rule TTP_XOR_MULT_DOSStub_2b43 {
  strings:
    $key_2b43 = { 7f 2b [2] 0b 33 [2] 4c 31 [2] 0b 20 [2] 45 2c [2] 49 26 [2] 5e 2d [2] 45 63 [2] 78 }

  condition:
    any of them
}