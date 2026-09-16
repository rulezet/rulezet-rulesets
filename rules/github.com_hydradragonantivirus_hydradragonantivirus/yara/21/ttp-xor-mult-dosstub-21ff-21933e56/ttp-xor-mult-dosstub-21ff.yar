rule TTP_XOR_MULT_DOSStub_21ff {
  strings:
    $key_21ff = { 75 97 [2] 01 8f [2] 46 8d [2] 01 9c [2] 4f 90 [2] 43 9a [2] 54 91 [2] 4f df [2] 72 }

  condition:
    any of them
}