rule TTP_XOR_MULT_DOSStub_68ff {
  strings:
    $key_68ff = { 3c 97 [2] 48 8f [2] 0f 8d [2] 48 9c [2] 06 90 [2] 0a 9a [2] 1d 91 [2] 06 df [2] 3b }

  condition:
    any of them
}