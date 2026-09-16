rule TTP_XOR_MULT_DOSStub_d46a {
  strings:
    $key_d46a = { 80 02 [2] f4 1a [2] b3 18 [2] f4 09 [2] ba 05 [2] b6 0f [2] a1 04 [2] ba 4a [2] 87 }

  condition:
    any of them
}