rule TTP_XOR_MULT_DOSStub_07ff {
  strings:
    $key_07ff = { 53 97 [2] 27 8f [2] 60 8d [2] 27 9c [2] 69 90 [2] 65 9a [2] 72 91 [2] 69 df [2] 54 }

  condition:
    any of them
}