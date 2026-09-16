rule TTP_XOR_MULT_DOSStub_2715 {
  strings:
    $key_2715 = { 73 7d [2] 07 65 [2] 40 67 [2] 07 76 [2] 49 7a [2] 45 70 [2] 52 7b [2] 49 35 [2] 74 }

  condition:
    any of them
}