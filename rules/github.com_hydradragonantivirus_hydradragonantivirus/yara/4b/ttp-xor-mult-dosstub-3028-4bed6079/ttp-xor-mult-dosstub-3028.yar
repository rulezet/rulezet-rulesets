rule TTP_XOR_MULT_DOSStub_3028 {
  strings:
    $key_3028 = { 64 40 [2] 10 58 [2] 57 5a [2] 10 4b [2] 5e 47 [2] 52 4d [2] 45 46 [2] 5e 08 [2] 63 }

  condition:
    any of them
}