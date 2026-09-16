rule TTP_XOR_MULT_DOSStub_6fe8 {
  strings:
    $key_6fe8 = { 3b 80 [2] 4f 98 [2] 08 9a [2] 4f 8b [2] 01 87 [2] 0d 8d [2] 1a 86 [2] 01 c8 [2] 3c }

  condition:
    any of them
}