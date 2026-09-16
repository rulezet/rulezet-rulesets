rule TTP_XOR_MULT_DOSStub_566a {
  strings:
    $key_566a = { 02 02 [2] 76 1a [2] 31 18 [2] 76 09 [2] 38 05 [2] 34 0f [2] 23 04 [2] 38 4a [2] 05 }

  condition:
    any of them
}