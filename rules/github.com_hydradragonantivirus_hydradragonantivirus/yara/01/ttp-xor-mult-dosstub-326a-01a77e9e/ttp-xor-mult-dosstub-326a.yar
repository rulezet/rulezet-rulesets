rule TTP_XOR_MULT_DOSStub_326a {
  strings:
    $key_326a = { 66 02 [2] 12 1a [2] 55 18 [2] 12 09 [2] 5c 05 [2] 50 0f [2] 47 04 [2] 5c 4a [2] 61 }

  condition:
    any of them
}