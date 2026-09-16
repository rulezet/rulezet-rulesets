rule TTP_XOR_MULT_DOSStub_216a {
  strings:
    $key_216a = { 75 02 [2] 01 1a [2] 46 18 [2] 01 09 [2] 4f 05 [2] 43 0f [2] 54 04 [2] 4f 4a [2] 72 }

  condition:
    any of them
}