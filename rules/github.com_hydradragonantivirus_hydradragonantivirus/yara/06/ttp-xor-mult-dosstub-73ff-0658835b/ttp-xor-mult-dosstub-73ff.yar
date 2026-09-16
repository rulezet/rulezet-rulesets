rule TTP_XOR_MULT_DOSStub_73ff {
  strings:
    $key_73ff = { 27 97 [2] 53 8f [2] 14 8d [2] 53 9c [2] 1d 90 [2] 11 9a [2] 06 91 [2] 1d df [2] 20 }

  condition:
    any of them
}