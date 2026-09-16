rule TTP_XOR_MULT_DOSStub_03ff {
  strings:
    $key_03ff = { 57 97 [2] 23 8f [2] 64 8d [2] 23 9c [2] 6d 90 [2] 61 9a [2] 76 91 [2] 6d df [2] 50 }

  condition:
    any of them
}