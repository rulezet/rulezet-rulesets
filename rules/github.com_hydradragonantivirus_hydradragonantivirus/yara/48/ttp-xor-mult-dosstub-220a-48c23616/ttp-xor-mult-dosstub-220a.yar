rule TTP_XOR_MULT_DOSStub_220a {
  strings:
    $key_220a = { 76 62 [2] 02 7a [2] 45 78 [2] 02 69 [2] 4c 65 [2] 40 6f [2] 57 64 [2] 4c 2a [2] 71 }

  condition:
    any of them
}