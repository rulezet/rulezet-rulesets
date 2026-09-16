rule TTP_XOR_MULT_DOSStub_2b45 {
  strings:
    $key_2b45 = { 7f 2d [2] 0b 35 [2] 4c 37 [2] 0b 26 [2] 45 2a [2] 49 20 [2] 5e 2b [2] 45 65 [2] 78 }

  condition:
    any of them
}