rule TTP_XOR_MULT_DOSStub_72e8 {
  strings:
    $key_72e8 = { 26 80 [2] 52 98 [2] 15 9a [2] 52 8b [2] 1c 87 [2] 10 8d [2] 07 86 [2] 1c c8 [2] 21 }

  condition:
    any of them
}