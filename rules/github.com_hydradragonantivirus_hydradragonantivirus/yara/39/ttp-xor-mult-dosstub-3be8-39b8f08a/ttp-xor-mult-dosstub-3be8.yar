rule TTP_XOR_MULT_DOSStub_3be8 {
  strings:
    $key_3be8 = { 6f 80 [2] 1b 98 [2] 5c 9a [2] 1b 8b [2] 55 87 [2] 59 8d [2] 4e 86 [2] 55 c8 [2] 68 }

  condition:
    any of them
}