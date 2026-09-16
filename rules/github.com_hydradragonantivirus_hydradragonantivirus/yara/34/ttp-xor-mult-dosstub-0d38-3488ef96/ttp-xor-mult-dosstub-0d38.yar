rule TTP_XOR_MULT_DOSStub_0d38 {
  strings:
    $key_0d38 = { 59 50 [2] 2d 48 [2] 6a 4a [2] 2d 5b [2] 63 57 [2] 6f 5d [2] 78 56 [2] 63 18 [2] 5e }

  condition:
    any of them
}