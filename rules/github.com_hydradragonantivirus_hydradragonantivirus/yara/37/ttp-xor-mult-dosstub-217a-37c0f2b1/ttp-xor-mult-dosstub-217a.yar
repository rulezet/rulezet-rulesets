rule TTP_XOR_MULT_DOSStub_217a {
  strings:
    $key_217a = { 75 12 [2] 01 0a [2] 46 08 [2] 01 19 [2] 4f 15 [2] 43 1f [2] 54 14 [2] 4f 5a [2] 72 }

  condition:
    any of them
}