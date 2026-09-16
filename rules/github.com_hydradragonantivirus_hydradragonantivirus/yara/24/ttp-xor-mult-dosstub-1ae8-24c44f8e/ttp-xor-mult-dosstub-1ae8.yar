rule TTP_XOR_MULT_DOSStub_1ae8 {
  strings:
    $key_1ae8 = { 4e 80 [2] 3a 98 [2] 7d 9a [2] 3a 8b [2] 74 87 [2] 78 8d [2] 6f 86 [2] 74 c8 [2] 49 }

  condition:
    any of them
}