rule TTP_XOR_MULT_DOSStub_2e6a {
  strings:
    $key_2e6a = { 7a 02 [2] 0e 1a [2] 49 18 [2] 0e 09 [2] 40 05 [2] 4c 0f [2] 5b 04 [2] 40 4a [2] 7d }

  condition:
    any of them
}