rule TTP_XOR_MULT_DOSStub_23ff {
  strings:
    $key_23ff = { 77 97 [2] 03 8f [2] 44 8d [2] 03 9c [2] 4d 90 [2] 41 9a [2] 56 91 [2] 4d df [2] 70 }

  condition:
    any of them
}