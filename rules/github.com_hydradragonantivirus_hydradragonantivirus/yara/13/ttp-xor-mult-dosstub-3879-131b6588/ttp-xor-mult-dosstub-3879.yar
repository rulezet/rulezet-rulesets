rule TTP_XOR_MULT_DOSStub_3879 {
  strings:
    $key_3879 = { 6c 11 [2] 18 09 [2] 5f 0b [2] 18 1a [2] 56 16 [2] 5a 1c [2] 4d 17 [2] 56 59 [2] 6b }

  condition:
    any of them
}