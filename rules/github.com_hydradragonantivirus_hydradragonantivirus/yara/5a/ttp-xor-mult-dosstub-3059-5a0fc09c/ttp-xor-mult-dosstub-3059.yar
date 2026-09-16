rule TTP_XOR_MULT_DOSStub_3059 {
  strings:
    $key_3059 = { 64 31 [2] 10 29 [2] 57 2b [2] 10 3a [2] 5e 36 [2] 52 3c [2] 45 37 [2] 5e 79 [2] 63 }

  condition:
    any of them
}