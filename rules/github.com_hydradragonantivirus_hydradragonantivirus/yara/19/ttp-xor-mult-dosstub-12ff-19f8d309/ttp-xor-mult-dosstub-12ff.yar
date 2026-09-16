rule TTP_XOR_MULT_DOSStub_12ff {
  strings:
    $key_12ff = { 46 97 [2] 32 8f [2] 75 8d [2] 32 9c [2] 7c 90 [2] 70 9a [2] 67 91 [2] 7c df [2] 41 }

  condition:
    any of them
}