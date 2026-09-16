rule TTP_XOR_MULT_DOSStub_410a {
  strings:
    $key_410a = { 15 62 [2] 61 7a [2] 26 78 [2] 61 69 [2] 2f 65 [2] 23 6f [2] 34 64 [2] 2f 2a [2] 12 }

  condition:
    any of them
}