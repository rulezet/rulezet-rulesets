rule TTP_XOR_MULT_DOSStub_256a {
  strings:
    $key_256a = { 71 02 [2] 05 1a [2] 42 18 [2] 05 09 [2] 4b 05 [2] 47 0f [2] 50 04 [2] 4b 4a [2] 76 }

  condition:
    any of them
}