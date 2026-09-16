rule TTP_XOR_MULT_DOSStub_576a {
  strings:
    $key_576a = { 03 02 [2] 77 1a [2] 30 18 [2] 77 09 [2] 39 05 [2] 35 0f [2] 22 04 [2] 39 4a [2] 04 }

  condition:
    any of them
}