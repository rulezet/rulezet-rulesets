rule TTP_XOR_MULT_DOSStub_50e5 {
  strings:
    $key_50e5 = { 04 8d [2] 70 95 [2] 37 97 [2] 70 86 [2] 3e 8a [2] 32 80 [2] 25 8b [2] 3e c5 [2] 03 }

  condition:
    any of them
}