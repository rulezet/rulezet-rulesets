rule TTP_XOR_MULT_DOSStub_2b25 {
  strings:
    $key_2b25 = { 7f 4d [2] 0b 55 [2] 4c 57 [2] 0b 46 [2] 45 4a [2] 49 40 [2] 5e 4b [2] 45 05 [2] 78 }

  condition:
    any of them
}