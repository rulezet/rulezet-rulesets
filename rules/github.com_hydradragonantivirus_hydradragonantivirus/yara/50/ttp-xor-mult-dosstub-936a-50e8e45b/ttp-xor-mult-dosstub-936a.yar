rule TTP_XOR_MULT_DOSStub_936a {
  strings:
    $key_936a = { c7 02 [2] b3 1a [2] f4 18 [2] b3 09 [2] fd 05 [2] f1 0f [2] e6 04 [2] fd 4a [2] c0 }

  condition:
    any of them
}