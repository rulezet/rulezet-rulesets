rule TTP_XOR_MULT_DOSStub_02e8 {
  strings:
    $key_02e8 = { 56 80 [2] 22 98 [2] 65 9a [2] 22 8b [2] 6c 87 [2] 60 8d [2] 77 86 [2] 6c c8 [2] 51 }

  condition:
    any of them
}