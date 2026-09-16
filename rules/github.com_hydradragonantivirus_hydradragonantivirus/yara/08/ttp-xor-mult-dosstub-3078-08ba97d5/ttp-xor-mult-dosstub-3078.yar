rule TTP_XOR_MULT_DOSStub_3078 {
  strings:
    $key_3078 = { 64 10 [2] 10 08 [2] 57 0a [2] 10 1b [2] 5e 17 [2] 52 1d [2] 45 16 [2] 5e 58 [2] 63 }

  condition:
    any of them
}