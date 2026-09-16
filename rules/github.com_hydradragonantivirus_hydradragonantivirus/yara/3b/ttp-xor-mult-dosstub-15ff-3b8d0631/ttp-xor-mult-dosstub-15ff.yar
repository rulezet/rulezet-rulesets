rule TTP_XOR_MULT_DOSStub_15ff {
  strings:
    $key_15ff = { 41 97 [2] 35 8f [2] 72 8d [2] 35 9c [2] 7b 90 [2] 77 9a [2] 60 91 [2] 7b df [2] 46 }

  condition:
    any of them
}