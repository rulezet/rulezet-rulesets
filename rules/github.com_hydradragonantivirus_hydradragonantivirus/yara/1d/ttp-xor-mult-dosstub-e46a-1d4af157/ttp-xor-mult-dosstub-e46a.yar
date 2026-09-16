rule TTP_XOR_MULT_DOSStub_e46a {
  strings:
    $key_e46a = { b0 02 [2] c4 1a [2] 83 18 [2] c4 09 [2] 8a 05 [2] 86 0f [2] 91 04 [2] 8a 4a [2] b7 }

  condition:
    any of them
}