rule TTP_XOR_MULT_DOSStub_2b68 {
  strings:
    $key_2b68 = { 7f 00 [2] 0b 18 [2] 4c 1a [2] 0b 0b [2] 45 07 [2] 49 0d [2] 5e 06 [2] 45 48 [2] 78 }

  condition:
    any of them
}