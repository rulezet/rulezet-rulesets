rule TTP_XOR_MULT_DOSStub_161a {
  strings:
    $key_161a = { 42 72 [2] 36 6a [2] 71 68 [2] 36 79 [2] 78 75 [2] 74 7f [2] 63 74 [2] 78 3a [2] 45 }

  condition:
    any of them
}