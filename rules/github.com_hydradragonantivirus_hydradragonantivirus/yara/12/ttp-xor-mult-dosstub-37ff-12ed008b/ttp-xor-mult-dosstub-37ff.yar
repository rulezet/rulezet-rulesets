rule TTP_XOR_MULT_DOSStub_37ff {
  strings:
    $key_37ff = { 63 97 [2] 17 8f [2] 50 8d [2] 17 9c [2] 59 90 [2] 55 9a [2] 42 91 [2] 59 df [2] 64 }

  condition:
    any of them
}