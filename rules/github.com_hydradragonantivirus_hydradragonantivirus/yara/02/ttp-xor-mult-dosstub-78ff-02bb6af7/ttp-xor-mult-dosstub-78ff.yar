rule TTP_XOR_MULT_DOSStub_78ff {
  strings:
    $key_78ff = { 2c 97 [2] 58 8f [2] 1f 8d [2] 58 9c [2] 16 90 [2] 1a 9a [2] 0d 91 [2] 16 df [2] 2b }

  condition:
    any of them
}