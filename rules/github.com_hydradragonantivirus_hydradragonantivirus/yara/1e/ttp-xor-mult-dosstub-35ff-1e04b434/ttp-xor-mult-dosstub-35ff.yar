rule TTP_XOR_MULT_DOSStub_35ff {
  strings:
    $key_35ff = { 61 97 [2] 15 8f [2] 52 8d [2] 15 9c [2] 5b 90 [2] 57 9a [2] 40 91 [2] 5b df [2] 66 }

  condition:
    any of them
}