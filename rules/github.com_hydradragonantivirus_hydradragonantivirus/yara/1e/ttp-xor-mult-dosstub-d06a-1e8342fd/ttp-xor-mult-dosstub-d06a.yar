rule TTP_XOR_MULT_DOSStub_d06a {
  strings:
    $key_d06a = { 84 02 [2] f0 1a [2] b7 18 [2] f0 09 [2] be 05 [2] b2 0f [2] a5 04 [2] be 4a [2] 83 }

  condition:
    any of them
}