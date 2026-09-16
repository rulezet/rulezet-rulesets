rule TTP_XOR_MULT_DOSStub_076a {
  strings:
    $key_076a = { 53 02 [2] 27 1a [2] 60 18 [2] 27 09 [2] 69 05 [2] 65 0f [2] 72 04 [2] 69 4a [2] 54 }

  condition:
    any of them
}