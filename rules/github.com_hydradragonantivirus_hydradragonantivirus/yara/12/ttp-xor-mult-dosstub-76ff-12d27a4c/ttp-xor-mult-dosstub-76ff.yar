rule TTP_XOR_MULT_DOSStub_76ff {
  strings:
    $key_76ff = { 22 97 [2] 56 8f [2] 11 8d [2] 56 9c [2] 18 90 [2] 14 9a [2] 03 91 [2] 18 df [2] 25 }

  condition:
    any of them
}