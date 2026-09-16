rule TTP_XOR_MULT_DOSStub_6b6a {
  strings:
    $key_6b6a = { 3f 02 [2] 4b 1a [2] 0c 18 [2] 4b 09 [2] 05 05 [2] 09 0f [2] 1e 04 [2] 05 4a [2] 38 }

  condition:
    any of them
}