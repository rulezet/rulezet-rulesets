rule TTP_XOR_MULT_DOSStub_6cff {
  strings:
    $key_6cff = { 38 97 [2] 4c 8f [2] 0b 8d [2] 4c 9c [2] 02 90 [2] 0e 9a [2] 19 91 [2] 02 df [2] 3f }

  condition:
    any of them
}