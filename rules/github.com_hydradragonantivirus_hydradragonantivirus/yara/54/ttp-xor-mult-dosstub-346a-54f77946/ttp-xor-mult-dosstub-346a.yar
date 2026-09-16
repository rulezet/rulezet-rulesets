rule TTP_XOR_MULT_DOSStub_346a {
  strings:
    $key_346a = { 60 02 [2] 14 1a [2] 53 18 [2] 14 09 [2] 5a 05 [2] 56 0f [2] 41 04 [2] 5a 4a [2] 67 }

  condition:
    any of them
}