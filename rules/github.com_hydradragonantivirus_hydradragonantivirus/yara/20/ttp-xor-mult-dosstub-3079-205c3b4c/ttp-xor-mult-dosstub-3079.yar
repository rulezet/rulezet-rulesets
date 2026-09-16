rule TTP_XOR_MULT_DOSStub_3079 {
  strings:
    $key_3079 = { 64 11 [2] 10 09 [2] 57 0b [2] 10 1a [2] 5e 16 [2] 52 1c [2] 45 17 [2] 5e 59 [2] 63 }

  condition:
    any of them
}