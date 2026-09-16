rule TTP_XOR_MULT_DOSStub_006a {
  strings:
    $key_006a = { 54 02 [2] 20 1a [2] 67 18 [2] 20 09 [2] 6e 05 [2] 62 0f [2] 75 04 [2] 6e 4a [2] 53 }

  condition:
    any of them
}