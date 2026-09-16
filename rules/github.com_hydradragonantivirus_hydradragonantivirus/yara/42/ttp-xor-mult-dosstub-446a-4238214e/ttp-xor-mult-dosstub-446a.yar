rule TTP_XOR_MULT_DOSStub_446a {
  strings:
    $key_446a = { 10 02 [2] 64 1a [2] 23 18 [2] 64 09 [2] 2a 05 [2] 26 0f [2] 31 04 [2] 2a 4a [2] 17 }

  condition:
    any of them
}