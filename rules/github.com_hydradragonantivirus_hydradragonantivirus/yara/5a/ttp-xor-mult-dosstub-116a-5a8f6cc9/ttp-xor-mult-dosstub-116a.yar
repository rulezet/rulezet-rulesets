rule TTP_XOR_MULT_DOSStub_116a {
  strings:
    $key_116a = { 45 02 [2] 31 1a [2] 76 18 [2] 31 09 [2] 7f 05 [2] 73 0f [2] 64 04 [2] 7f 4a [2] 42 }

  condition:
    any of them
}