rule TTP_XOR_MULT_DOSStub_44ff {
  strings:
    $key_44ff = { 10 97 [2] 64 8f [2] 23 8d [2] 64 9c [2] 2a 90 [2] 26 9a [2] 31 91 [2] 2a df [2] 17 }

  condition:
    any of them
}