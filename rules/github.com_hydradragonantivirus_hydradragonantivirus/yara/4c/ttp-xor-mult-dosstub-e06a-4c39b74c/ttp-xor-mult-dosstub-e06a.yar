rule TTP_XOR_MULT_DOSStub_e06a {
  strings:
    $key_e06a = { b4 02 [2] c0 1a [2] 87 18 [2] c0 09 [2] 8e 05 [2] 82 0f [2] 95 04 [2] 8e 4a [2] b3 }

  condition:
    any of them
}