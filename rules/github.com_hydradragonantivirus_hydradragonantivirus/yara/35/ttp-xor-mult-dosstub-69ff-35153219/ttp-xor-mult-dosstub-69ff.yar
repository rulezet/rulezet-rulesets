rule TTP_XOR_MULT_DOSStub_69ff {
  strings:
    $key_69ff = { 3d 97 [2] 49 8f [2] 0e 8d [2] 49 9c [2] 07 90 [2] 0b 9a [2] 1c 91 [2] 07 df [2] 3a }

  condition:
    any of them
}