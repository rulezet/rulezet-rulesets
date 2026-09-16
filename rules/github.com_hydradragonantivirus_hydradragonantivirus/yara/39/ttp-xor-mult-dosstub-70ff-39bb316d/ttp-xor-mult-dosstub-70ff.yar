rule TTP_XOR_MULT_DOSStub_70ff {
  strings:
    $key_70ff = { 24 97 [2] 50 8f [2] 17 8d [2] 50 9c [2] 1e 90 [2] 12 9a [2] 05 91 [2] 1e df [2] 23 }

  condition:
    any of them
}