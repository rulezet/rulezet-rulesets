rule TTP_XOR_MULT_DOSStub_2ae8 {
  strings:
    $key_2ae8 = { 7e 80 [2] 0a 98 [2] 4d 9a [2] 0a 8b [2] 44 87 [2] 48 8d [2] 5f 86 [2] 44 c8 [2] 79 }

  condition:
    any of them
}