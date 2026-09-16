rule TTP_XOR_MULT_DOSStub_3073 {
  strings:
    $key_3073 = { 64 1b [2] 10 03 [2] 57 01 [2] 10 10 [2] 5e 1c [2] 52 16 [2] 45 1d [2] 5e 53 [2] 63 }

  condition:
    any of them
}