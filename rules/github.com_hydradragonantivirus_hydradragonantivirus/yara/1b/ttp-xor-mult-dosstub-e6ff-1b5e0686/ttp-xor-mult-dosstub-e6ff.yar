rule TTP_XOR_MULT_DOSStub_e6ff {
  strings:
    $key_e6ff = { b2 97 [2] c6 8f [2] 81 8d [2] c6 9c [2] 88 90 [2] 84 9a [2] 93 91 [2] 88 df [2] b5 }

  condition:
    any of them
}