rule TTP_XOR_MULT_DOSStub_0a64 {
  strings:
    $key_0a64 = { 5e 0c [2] 2a 14 [2] 6d 16 [2] 2a 07 [2] 64 0b [2] 68 01 [2] 7f 0a [2] 64 44 [2] 59 }

  condition:
    any of them
}