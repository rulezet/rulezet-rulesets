rule TTP_XOR_MULT_DOSStub_12e8 {
  strings:
    $key_12e8 = { 46 80 [2] 32 98 [2] 75 9a [2] 32 8b [2] 7c 87 [2] 70 8d [2] 67 86 [2] 7c c8 [2] 41 }

  condition:
    any of them
}