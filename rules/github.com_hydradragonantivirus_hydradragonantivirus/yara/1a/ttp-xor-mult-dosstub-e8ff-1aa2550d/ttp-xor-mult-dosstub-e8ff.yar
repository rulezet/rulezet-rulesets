rule TTP_XOR_MULT_DOSStub_e8ff {
  strings:
    $key_e8ff = { bc 97 [2] c8 8f [2] 8f 8d [2] c8 9c [2] 86 90 [2] 8a 9a [2] 9d 91 [2] 86 df [2] bb }

  condition:
    any of them
}