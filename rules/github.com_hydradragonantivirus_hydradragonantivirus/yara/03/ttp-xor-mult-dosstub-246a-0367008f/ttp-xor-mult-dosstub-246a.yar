rule TTP_XOR_MULT_DOSStub_246a {
  strings:
    $key_246a = { 70 02 [2] 04 1a [2] 43 18 [2] 04 09 [2] 4a 05 [2] 46 0f [2] 51 04 [2] 4a 4a [2] 77 }

  condition:
    any of them
}