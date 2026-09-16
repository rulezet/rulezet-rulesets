rule TTP_XOR_MULT_DOSStub_63ff {
  strings:
    $key_63ff = { 37 97 [2] 43 8f [2] 04 8d [2] 43 9c [2] 0d 90 [2] 01 9a [2] 16 91 [2] 0d df [2] 30 }

  condition:
    any of them
}