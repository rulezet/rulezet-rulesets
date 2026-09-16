rule TTP_XOR_MULT_DOSStub_164a {
  strings:
    $key_164a = { 42 22 [2] 36 3a [2] 71 38 [2] 36 29 [2] 78 25 [2] 74 2f [2] 63 24 [2] 78 6a [2] 45 }

  condition:
    any of them
}