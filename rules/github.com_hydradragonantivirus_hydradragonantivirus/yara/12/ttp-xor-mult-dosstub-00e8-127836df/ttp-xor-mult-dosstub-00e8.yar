rule TTP_XOR_MULT_DOSStub_00e8 {
  strings:
    $key_00e8 = { 54 80 [2] 20 98 [2] 67 9a [2] 20 8b [2] 6e 87 [2] 62 8d [2] 75 86 [2] 6e c8 [2] 53 }

  condition:
    any of them
}