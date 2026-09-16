rule TTP_XOR_MULT_DOSStub_3ae8 {
  strings:
    $key_3ae8 = { 6e 80 [2] 1a 98 [2] 5d 9a [2] 1a 8b [2] 54 87 [2] 58 8d [2] 4f 86 [2] 54 c8 [2] 69 }

  condition:
    any of them
}