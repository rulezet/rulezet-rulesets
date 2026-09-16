rule TTP_XOR_MULT_DOSStub_30ff {
  strings:
    $key_30ff = { 64 97 [2] 10 8f [2] 57 8d [2] 10 9c [2] 5e 90 [2] 52 9a [2] 45 91 [2] 5e df [2] 63 }

  condition:
    any of them
}