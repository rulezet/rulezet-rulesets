rule TTP_XOR_MULT_DOSStub_6514 {
  strings:
    $key_6514 = { 31 7c [2] 45 64 [2] 02 66 [2] 45 77 [2] 0b 7b [2] 07 71 [2] 10 7a [2] 0b 34 [2] 36 }

  condition:
    any of them
}