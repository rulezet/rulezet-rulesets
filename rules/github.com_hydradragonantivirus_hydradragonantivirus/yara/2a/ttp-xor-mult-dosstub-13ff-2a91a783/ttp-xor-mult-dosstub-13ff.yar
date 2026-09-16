rule TTP_XOR_MULT_DOSStub_13ff {
  strings:
    $key_13ff = { 47 97 [2] 33 8f [2] 74 8d [2] 33 9c [2] 7d 90 [2] 71 9a [2] 66 91 [2] 7d df [2] 40 }

  condition:
    any of them
}