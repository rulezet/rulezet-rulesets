rule TTP_XOR_MULT_DOSStub_41ff {
  strings:
    $key_41ff = { 15 97 [2] 61 8f [2] 26 8d [2] 61 9c [2] 2f 90 [2] 23 9a [2] 34 91 [2] 2f df [2] 12 }

  condition:
    any of them
}