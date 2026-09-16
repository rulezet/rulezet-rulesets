rule TTP_XOR_MULT_DOSStub_686a {
  strings:
    $key_686a = { 3c 02 [2] 48 1a [2] 0f 18 [2] 48 09 [2] 06 05 [2] 0a 0f [2] 1d 04 [2] 06 4a [2] 3b }

  condition:
    any of them
}