rule TTP_XOR_MULT_DOSStub_1ee8 {
  strings:
    $key_1ee8 = { 4a 80 [2] 3e 98 [2] 79 9a [2] 3e 8b [2] 70 87 [2] 7c 8d [2] 6b 86 [2] 70 c8 [2] 4d }

  condition:
    any of them
}