rule TTP_XOR_MULT_DOSStub_0d2a {
  strings:
    $key_0d2a = { 59 42 [2] 2d 5a [2] 6a 58 [2] 2d 49 [2] 63 45 [2] 6f 4f [2] 78 44 [2] 63 0a [2] 5e }

  condition:
    any of them
}