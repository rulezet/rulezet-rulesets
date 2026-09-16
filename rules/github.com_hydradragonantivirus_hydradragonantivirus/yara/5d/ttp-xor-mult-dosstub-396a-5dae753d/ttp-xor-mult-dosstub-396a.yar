rule TTP_XOR_MULT_DOSStub_396a {
  strings:
    $key_396a = { 6d 02 [2] 19 1a [2] 5e 18 [2] 19 09 [2] 57 05 [2] 5b 0f [2] 4c 04 [2] 57 4a [2] 6a }

  condition:
    any of them
}