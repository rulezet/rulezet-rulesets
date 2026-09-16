rule TTP_XOR_MULT_DOSStub_09e8 {
  strings:
    $key_09e8 = { 5d 80 [2] 29 98 [2] 6e 9a [2] 29 8b [2] 67 87 [2] 6b 8d [2] 7c 86 [2] 67 c8 [2] 5a }

  condition:
    any of them
}