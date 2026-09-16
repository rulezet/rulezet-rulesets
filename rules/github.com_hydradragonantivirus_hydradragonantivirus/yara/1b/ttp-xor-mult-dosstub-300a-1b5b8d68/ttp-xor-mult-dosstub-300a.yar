rule TTP_XOR_MULT_DOSStub_300a {
  strings:
    $key_300a = { 64 62 [2] 10 7a [2] 57 78 [2] 10 69 [2] 5e 65 [2] 52 6f [2] 45 64 [2] 5e 2a [2] 63 }

  condition:
    any of them
}