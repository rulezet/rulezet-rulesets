rule TTP_XOR_MULT_DOSStub_31ff {
  strings:
    $key_31ff = { 65 97 [2] 11 8f [2] 56 8d [2] 11 9c [2] 5f 90 [2] 53 9a [2] 44 91 [2] 5f df [2] 62 }

  condition:
    any of them
}