rule TTP_XOR_MULT_DOSStub_0d35 {
  strings:
    $key_0d35 = { 59 5d [2] 2d 45 [2] 6a 47 [2] 2d 56 [2] 63 5a [2] 6f 50 [2] 78 5b [2] 63 15 [2] 5e }

  condition:
    any of them
}