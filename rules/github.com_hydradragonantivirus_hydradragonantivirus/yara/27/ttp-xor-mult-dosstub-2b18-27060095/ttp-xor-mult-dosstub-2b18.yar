rule TTP_XOR_MULT_DOSStub_2b18 {
  strings:
    $key_2b18 = { 7f 70 [2] 0b 68 [2] 4c 6a [2] 0b 7b [2] 45 77 [2] 49 7d [2] 5e 76 [2] 45 38 [2] 78 }

  condition:
    any of them
}