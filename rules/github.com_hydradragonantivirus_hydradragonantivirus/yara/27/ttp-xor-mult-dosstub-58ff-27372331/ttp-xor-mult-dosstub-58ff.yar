rule TTP_XOR_MULT_DOSStub_58ff {
  strings:
    $key_58ff = { 0c 97 [2] 78 8f [2] 3f 8d [2] 78 9c [2] 36 90 [2] 3a 9a [2] 2d 91 [2] 36 df [2] 0b }

  condition:
    any of them
}