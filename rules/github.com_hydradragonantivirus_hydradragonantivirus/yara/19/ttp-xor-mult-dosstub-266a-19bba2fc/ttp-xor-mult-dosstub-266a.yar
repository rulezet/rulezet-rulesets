rule TTP_XOR_MULT_DOSStub_266a {
  strings:
    $key_266a = { 72 02 [2] 06 1a [2] 41 18 [2] 06 09 [2] 48 05 [2] 44 0f [2] 53 04 [2] 48 4a [2] 75 }

  condition:
    any of them
}