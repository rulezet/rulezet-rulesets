rule TTP_XOR_MULT_DOSStub_22ff {
  strings:
    $key_22ff = { 76 97 [2] 02 8f [2] 45 8d [2] 02 9c [2] 4c 90 [2] 40 9a [2] 57 91 [2] 4c df [2] 71 }

  condition:
    any of them
}