rule TTP_XOR_MULT_DOSStub_223a {
  strings:
    $key_223a = { 76 52 [2] 02 4a [2] 45 48 [2] 02 59 [2] 4c 55 [2] 40 5f [2] 57 54 [2] 4c 1a [2] 71 }

  condition:
    any of them
}